"""请求体处理：gzip 解压、JSON 解析、事件校验与稳定摘要。

注意：本模块只在签名验证通过之后才会被调用（见 server.py 的处理顺序）。
"""
from __future__ import annotations

import hashlib
import json
import zlib

from .errors import ApiError

_GZIP_MAGIC = b"\x1f\x8b"


def maybe_decompress(raw: bytes, content_encoding: str | None, max_out: int) -> bytes:
    """按 Content-Encoding（或 gzip 魔数）解压，带解压后大小上限。"""
    encoding = (content_encoding or "identity").strip().lower()
    if encoding in ("identity", ""):
        if raw[:2] == _GZIP_MAGIC:
            encoding = "gzip"  # 客户端漏标 Content-Encoding 时按魔数识别
        else:
            return raw
    if encoding != "gzip":
        raise ApiError(415, "UNSUPPORTED_ENCODING",
                       f"unsupported Content-Encoding: {content_encoding}")
    return _bounded_gunzip(raw, max_out)


def _bounded_gunzip(raw: bytes, max_out: int) -> bytes:
    if raw[:2] != _GZIP_MAGIC:
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       "Content-Encoding is gzip but body lacks gzip magic bytes")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decompressor.decompress(raw, max_out + 1)
        if decompressor.unconsumed_tail:
            raise ApiError(413, "PAYLOAD_TOO_LARGE",
                           "decompressed payload exceeds limit")
        out += decompressor.flush()
    except zlib.error as exc:
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       f"invalid gzip stream: {exc}") from exc
    if len(out) > max_out:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", "decompressed payload exceeds limit")
    if not decompressor.eof:
        raise ApiError(400, "PAYLOAD_MALFORMED", "truncated gzip stream")
    return bytes(out)


def parse_and_validate(data: bytes, expected_station: str, now: float) -> dict:
    """解析并校验事件载荷；任何不满足都抛出 400 PAYLOAD_MALFORMED。"""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(400, "PAYLOAD_MALFORMED", "payload is not valid UTF-8") from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       f"payload is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ApiError(400, "PAYLOAD_MALFORMED", "payload must be a JSON object")

    station = obj.get("station_id")
    if not isinstance(station, str) or not station:
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       "payload.station_id must be a non-empty string")
    if station != expected_station:
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       "payload.station_id does not match X-Station-Id header",
                       detail=f"payload={station!r} header={expected_station!r}")

    events = obj.get("events")
    if not isinstance(events, list) or not events:
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       "payload.events must be a non-empty array")
    if len(events) > 1000:
        raise ApiError(400, "PAYLOAD_MALFORMED", "payload.events exceeds 1000 entries")

    for index, event in enumerate(events):
        _validate_event(index, event, now)
    return obj


def _validate_event(index: int, event: object, now: float) -> None:
    where = f"events[{index}]"
    if not isinstance(event, dict):
        raise ApiError(400, "PAYLOAD_MALFORMED", f"{where} must be an object")
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not (1 <= len(event_id) <= 128):
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       f"{where}.event_id must be a string of 1..128 chars")
    measured_at = event.get("measured_at")
    if isinstance(measured_at, bool) or not isinstance(measured_at, (int, float)):
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       f"{where}.measured_at must be a number (unix seconds)")
    if not (0 < measured_at <= now + 86400):
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       f"{where}.measured_at out of plausible range")
    dose = event.get("dose_usv_h")
    if isinstance(dose, bool) or not isinstance(dose, (int, float)) \
            or not (0 <= dose <= 1e6):
        raise ApiError(400, "PAYLOAD_MALFORMED",
                       f"{where}.dose_usv_h must be a number within [0, 1e6]")


def _canonical_number(value):
    """把 JSON 数值归一到数值本身：1 与 1.0、0 与 -0.0 的规范化结果相同。

    JSON 中 1（整数文本）与 1.0（等值浮点文本）解析后分别是 int 与 float，
    直接序列化会得到不同文本、进而产生不同摘要；这里统一按浮点值输出，
    使“数值相等即同一事件”。布尔值不是数值，必须原样保留（True != 1）。
    超过浮点精确范围的整数保留原整数，避免精度丢失导致误并（业务字段
    measured_at/dose_usv_h 远小于 2^53，不受影响）。
    """
    if isinstance(value, bool):  # 必须先于 int 判断：bool 是 int 的子类型
        return value
    if isinstance(value, int):
        number = float(value)
        if int(number) != value:  # 整数不能被 float 精确表示：保留原值
            return value
        value = number
    number = value + 0.0  # float：归一掉 -0.0
    if number == 0.0:
        number = 0.0
    return number


def _normalize_numbers(obj: object) -> object:
    """递归返回副本，把所有数值字段替换为 _canonical_number 的结果。"""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return _canonical_number(obj)
    if isinstance(obj, dict):
        return {key: _normalize_numbers(val) for key, val in obj.items()}
    if isinstance(obj, list):
        return [_normalize_numbers(item) for item in obj]
    return obj


def canonical_json(obj: object) -> str:
    """规范化 JSON：键排序、无空白，数值按数值本身归一，保证同一内容摘要稳定。

    归一覆盖两点：键序/空白差异（sort_keys + 紧凑分隔符）与数值文本差异
    （JSON 的 1 与 1.0 数值相等，规范化文本一致）。
    """
    normalized = _normalize_numbers(obj)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def stable_digest(obj: object) -> tuple[str, str]:
    """返回 (事件摘要 SHA-256 十六进制, 规范化 JSON 文本)。"""
    canonical = canonical_json(obj)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), canonical


def semantic_equal(left: object, right: object) -> bool:
    """按 JSON 数据值比较两个已解析对象：数值按值相等（1 == 1.0），其余按类型。

    与 Python 裸 == 不同，布尔值不与数值混同（true != 1），字符串/None 也不
    与数值隐式相等。用于恢复核对：旧数据卷中的回执按旧的整数文本保存摘要，
    仅凭摘要串无法识别等值浮点表示，需要比对事件内容本身。
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return _canonical_number(left) == _canonical_number(right)
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        if left.keys() != right.keys():
            return False
        return all(semantic_equal(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        return (len(left) == len(right)
                and all(semantic_equal(a, b) for a, b in zip(left, right)))
    return False


def canonical_payloads_equal(stored_canonical: str,
                             presented_canonical: str) -> bool:
    """比较两份规范化载荷 JSON 是否表示同一事件内容（数值按值比较）。"""
    try:
        stored = json.loads(stored_canonical)
        presented = json.loads(presented_canonical)
    except (json.JSONDecodeError, TypeError):
        return stored_canonical == presented_canonical
    return semantic_equal(stored, presented)
