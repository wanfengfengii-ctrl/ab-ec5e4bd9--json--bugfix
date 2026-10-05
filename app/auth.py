"""请求签名：规范化串构造、HMAC-SHA256 签名与恒定时间校验。

规范化串（各项以换行 "\\n" 连接，顺序固定）：

    POST
    /api/telemetry/events
    <X-Station-Id>
    <X-Key-Id>
    <X-Timestamp>
    <X-Nonce>
    <传输原始字节的 SHA-256 十六进制摘要>

签名 = Base64( HMAC-SHA256(key=密钥, msg=规范化串) )
"""
from __future__ import annotations

import base64
import hashlib
import hmac


def body_sha256_hex(raw_body: bytes) -> str:
    """传输原始字节（压缩态即压缩字节）的 SHA-256 十六进制摘要。"""
    return hashlib.sha256(raw_body).hexdigest()


def canonical_string(method: str, path: str, station_id: str, key_id: str,
                     timestamp: str, nonce: str, raw_body: bytes) -> str:
    return "\n".join([
        method,
        path,
        station_id,
        key_id,
        timestamp,
        nonce,
        body_sha256_hex(raw_body),
    ])


def sign(secret: str, canonical: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def sign_request(secret: str, method: str, path: str, station_id: str, key_id: str,
                 timestamp: str, nonce: str, raw_body: bytes) -> str:
    """客户端/测试辅助：对一次请求计算签名。"""
    return sign(secret, canonical_string(method, path, station_id, key_id,
                                         timestamp, nonce, raw_body))


def verify_signature(secret: str, canonical: str, signature_b64: str) -> bool:
    try:
        presented = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    expected = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"),
                        hashlib.sha256).digest()
    return hmac.compare_digest(presented, expected)
