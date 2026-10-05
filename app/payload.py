"""请求体处理：gzip 解压、JSON 解析、事件校验与稳定摘要。

注意：本模块只在签名验证通过之后才会被调用（见 server.py 的处理顺序）。
"""
from __future__ import annotations

import hashlib
import json
import math
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


def canonical_json(obj: object) -> str:
    """规范化 JSON：键排序、无空白，保证同一内容摘要稳定。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _normalized_for_digest(obj: object) -> object:
    """递归生成用于摘要的结构副本：把数值相等的整数与浮点统一表示。

    JSON 的 `1` 与 `1.0` 只是同一数值的不同文本表示；若不统一，恢复接口会
    把仅相差数字写法的同一事件误判为 RECEIPT_MISMATCH。统一规则：

    - bool 先排除（True/False 不是数字，载荷校验也不允许布尔出现在数值字段）；
    - 整数保持整数（任何 JSON 整数都按精确值保留，绝不无条件转 float——超过
      2^53 的大整数无法被 float64 精确表示，转换会让两个不同整数发生碰撞）；
    - 浮点仅在「转成整数后再转回 float 仍等于原值」时归并为整数，于是
      1.0/1.00/1e0/1 落到同一表示，而 9007199254740993.0（实际舍入为
      …992 的 float）不会错误并入整数 …993；
    - 其余浮点用 _CanonicalFloat 经 repr(float) 输出最短往返十进制文本，
      消除 1.50/1.5、100.0/1.0e2 之类的文本差异；
    - 非数值节点原样递归（dict/list/str/None 等）。

    归一化保持 Python 解析 JSON 后采用的数值相等语义：两个数字归一化结果
    相同，当且仅当它们解析出的数值相等。
    """
    if isinstance(obj, dict):
        return {key: _normalized_for_digest(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_normalized_for_digest(item) for item in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        if math.isfinite(obj):
            as_int = int(obj)
            if float(as_int) == obj:  # 整数值且整数可被该 float 精确表示
                return as_int
        return _CanonicalFloat(obj)
    return obj


class _CanonicalFloat(float):
    """float 子类：序列化时固定使用 repr 的最短往返表示（如 1.5、1e+308）。

    比较与哈希沿用 float；自定义 __repr__ 让 json.dumps 对非整数值输出统一
    的规范文本，不再受源码写法（尾零、指数写法）影响。
    """

    def __repr__(self) -> str:
        return repr(float(self))


def stable_digest(obj: object) -> tuple[str, str]:
    """返回 (事件摘要 SHA-256 十六进制, 规范化 JSON 文本)。

    摘要以数值归一化后的结构计算：键序、空白与传输编码（JSON/gzip）无关，
    且 JSON 数值相等的载荷（如 dose_usv_h 的 1 与 1.0）摘要一致。
    """
    normalized = _normalized_for_digest(obj)
    canonical = canonical_json(normalized)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), canonical
