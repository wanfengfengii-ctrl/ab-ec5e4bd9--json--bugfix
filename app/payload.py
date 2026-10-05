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


def canonical_json(obj: object) -> str:
    """规范化 JSON：键排序、无空白，保证同一内容摘要稳定。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_digest(obj: object) -> tuple[str, str]:
    """返回 (事件摘要 SHA-256 十六进制, 规范化 JSON 文本)。"""
    canonical = canonical_json(obj)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), canonical
