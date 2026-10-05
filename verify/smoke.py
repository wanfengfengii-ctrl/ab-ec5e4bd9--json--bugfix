"""对运行中的网关执行端到端冒烟：签名、压缩、时间窗、密钥有效期、防重放（含并发）
与丢失回执恢复（恢复/冲突/不泄露/不占 nonce）。

注：重启持久化与旧数据卷（仅有防重放记录）场景由单元测试覆盖，
verify.run 会先跑单元测试再执行本冒烟。
"""
from __future__ import annotations

import gzip
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from app import auth
from app.keystore import KeyStore
from app.payload import stable_digest

EVENTS_PATH = "/api/telemetry/events"
RECOVER_PATH = "/api/telemetry/events/recover"


class SmokeFailure(Exception):
    pass


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def _post(base_url: str, raw: bytes, headers: dict,
          path: str = EVENTS_PATH, timeout: float = 10.0) -> tuple[int, dict]:
    req = urllib.request.Request(base_url + path, data=raw,
                                 headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _headers_for(key, timestamp: int, nonce: str, raw: bytes,
                 secret: str | None = None, path: str = EVENTS_PATH) -> dict:
    signature = auth.sign_request(secret or key.secret, "POST", path,
                                  key.station_id, key.key_id, str(timestamp),
                                  nonce, raw)
    return {
        "X-Station-Id": key.station_id,
        "X-Key-Id": key.key_id,
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def _payload(station_id: str) -> dict:
    return {
        "station_id": station_id,
        "sent_at": int(time.time()),
        "events": [
            {"event_id": "evt-" + secrets.token_hex(4),
             "measured_at": int(time.time()) - 5,
             "dose_usv_h": 0.117, "instrument": "gm-1"},
        ],
    }


def _nonce() -> str:
    return secrets.token_hex(12)


def _tamper(sig: str) -> str:
    """保证篡改后的签名与原文不同（首字符换成另一个 Base64 字符）。"""
    return ("A" if sig[0] != "A" else "B") + sig[1:]


def run_smoke(base_url: str, keys_file: str) -> bool:
    keystore = KeyStore.load(keys_file)
    active = keystore.get("test-key-1")
    expired = keystore.get("test-key-expired")
    future = keystore.get("test-key-future")
    if not (active and expired and future):
        print("[smoke] keys file must define test-key-1 / test-key-expired / "
              "test-key-future")
        return False

    ctx: dict = {}

    # ---------- 签名与压缩 ----------
    def case_happy_json():
        payload = _payload(active.station_id)
        raw = json.dumps(payload).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202, f"expected 202, got {status}: {body}")
        expected, _ = stable_digest(payload)
        _expect(body.get("event_digest") == expected,
                f"digest mismatch: {body.get('event_digest')} != {expected}")
        ctx["json"] = (raw, headers, expected)
        ctx["accepted"] = body

    def case_happy_gzip_same_digest():
        raw_plain = json.dumps(_payload(active.station_id)).encode()
        compressed = gzip.compress(raw_plain)
        headers = _headers_for(active, int(time.time()), _nonce(), compressed)
        headers["Content-Encoding"] = "gzip"
        status, body = _post(base_url, compressed, headers)
        _expect(status == 202, f"expected 202, got {status}: {body}")
        expected, _ = stable_digest(json.loads(raw_plain.decode()))
        _expect(body.get("event_digest") == expected,
                "gzip payload digest should equal plain-json digest")

    def case_gzip_magic_without_header():
        compressed = gzip.compress(json.dumps(_payload(active.station_id)).encode())
        headers = _headers_for(active, int(time.time()), _nonce(), compressed)
        status, body = _post(base_url, compressed, headers)
        _expect(status == 202, f"expected 202, got {status}: {body}")

    def case_bad_signature():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        headers["X-Signature"] = _tamper(headers["X-Signature"])
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "SIGNATURE_INVALID",
                f"expected 401 SIGNATURE_INVALID, got {status}: {body}")

    def case_wrong_secret():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw,
                               secret="definitely-wrong-secret")
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "SIGNATURE_INVALID",
                f"expected 401 SIGNATURE_INVALID, got {status}: {body}")

    def case_unknown_key():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        headers["X-Key-Id"] = "no-such-key"
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "KEY_UNKNOWN",
                f"expected 401 KEY_UNKNOWN, got {status}: {body}")

    # ---------- 密钥有效期与时间窗 ----------
    def case_expired_key():
        raw = json.dumps(_payload(expired.station_id)).encode()
        headers = _headers_for(expired, int(time.time()), _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 403 and body["error"]["code"] == "KEY_EXPIRED",
                f"expected 403 KEY_EXPIRED, got {status}: {body}")

    def case_not_yet_valid_key():
        raw = json.dumps(_payload(future.station_id)).encode()
        headers = _headers_for(future, int(time.time()), _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 403 and body["error"]["code"] == "KEY_EXPIRED",
                f"expected 403 KEY_EXPIRED, got {status}: {body}")

    def case_stale_timestamp():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()) - 3600, _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "TIMESTAMP_OUT_OF_RANGE",
                f"expected 401 TIMESTAMP_OUT_OF_RANGE, got {status}: {body}")

    def case_future_timestamp():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()) + 3600, _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "TIMESTAMP_OUT_OF_RANGE",
                f"expected 401 TIMESTAMP_OUT_OF_RANGE, got {status}: {body}")

    # ---------- 畸形载荷 & 失败不占 nonce ----------
    def case_malformed_payload_then_retry_same_nonce():
        nonce = _nonce()
        bad_raw = b'{"station_id": "' + active.station_id.encode() + b'", broken'
        headers = _headers_for(active, int(time.time()), nonce, bad_raw)
        status, body = _post(base_url, bad_raw, headers)
        _expect(status == 400 and body["error"]["code"] == "PAYLOAD_MALFORMED",
                f"expected 400 PAYLOAD_MALFORMED, got {status}: {body}")
        # 失败请求不得占用 nonce：同一 nonce 换上合法载荷必须成功
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202,
                f"nonce consumed by failed request! got {status}: {body}")

    def case_bad_signature_does_not_consume_nonce():
        nonce = _nonce()
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        headers["X-Signature"] = _tamper(headers["X-Signature"])
        status, _ = _post(base_url, raw, headers)
        _expect(status == 401, f"expected 401, got {status}")
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202,
                f"nonce consumed by failed request! got {status}: {body}")

    # ---------- 防重放 ----------
    def case_replay_rejected():
        raw, headers, _ = ctx["json"]
        status, body = _post(base_url, raw, headers)  # 原样重放首个成功请求
        _expect(status == 409 and body["error"]["code"] == "NONCE_REPLAY",
                f"expected 409 NONCE_REPLAY, got {status}: {body}")

    def case_concurrent_replay_exactly_one_wins():
        raw = json.dumps(_payload(active.station_id)).encode()
        nonce = _nonce()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            return _post(base_url, raw, headers)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: worker(), range(16)))
        codes = [s for s, _ in results]
        _expect(codes.count(202) == 1,
                f"expected exactly one 202, got codes={codes}")
        _expect(codes.count(409) == 15,
                f"expected fifteen 409, got codes={codes}")
        ctx["concurrent"] = (raw, nonce)

    # ---------- 丢失回执的恢复 ----------
    def case_recover_happy():
        raw, headers, _ = ctx["json"]
        accepted = ctx["accepted"]
        nonce = headers["X-Nonce"]
        # 新的时刻与签名（路径换成恢复路径），载荷与 nonce 不变
        recover_headers = _headers_for(active, int(time.time()), nonce, raw,
                                       path=RECOVER_PATH)
        status, body = _post(base_url, raw, recover_headers, path=RECOVER_PATH)
        _expect(status == 200, f"expected 200, got {status}: {body}")
        _expect(body.get("status") == "recovered",
                f"expected status=recovered, got {body}")
        _expect(body.get("event_digest") == accepted["event_digest"],
                "recovered digest differs from accepted digest")
        _expect(body.get("received_at") == accepted["received_at"],
                "recovered received_at differs from accepted received_at")

    def case_recover_gzip_transport_independent():
        """gzip 接纳、明文恢复：同一事件内容摘要恒定，恢复与传输编码无关。"""
        payload = _payload(active.station_id)
        plain = json.dumps(payload).encode()
        compressed = gzip.compress(plain)
        nonce = _nonce()
        headers = _headers_for(active, int(time.time()), nonce, compressed)
        headers["Content-Encoding"] = "gzip"
        status, accepted = _post(base_url, compressed, headers)
        _expect(status == 202, f"expected 202, got {status}: {accepted}")
        recover_headers = _headers_for(active, int(time.time()), nonce, plain,
                                       path=RECOVER_PATH)
        status, body = _post(base_url, plain, recover_headers, path=RECOVER_PATH)
        _expect(status == 200, f"expected 200, got {status}: {body}")
        _expect(body.get("event_digest") == accepted["event_digest"],
                "recovered digest should equal gzip-accepted digest")

    def case_recover_unknown_nonce_404():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw,
                               path=RECOVER_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 404 and body["error"]["code"] == "RECEIPT_NOT_FOUND",
                f"expected 404 RECEIPT_NOT_FOUND, got {status}: {body}")

    def case_recover_mismatch_409():
        nonce = _nonce()
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, _ = _post(base_url, raw, headers)
        _expect(status == 202, f"accept failed: {status}")
        other = json.dumps(_payload(active.station_id)).encode()  # 同站点不同内容
        recover_headers = _headers_for(active, int(time.time()), nonce, other,
                                       path=RECOVER_PATH)
        status, body = _post(base_url, other, recover_headers, path=RECOVER_PATH)
        _expect(status == 409 and body["error"]["code"] == "RECEIPT_MISMATCH",
                f"expected 409 RECEIPT_MISMATCH, got {status}: {body}")

    def case_recover_signature_must_bind_recover_path():
        raw, _, _ = ctx["json"]
        nonce = _nonce()
        # 用事件路径签名打到恢复路径上：必须 401
        headers = _headers_for(active, int(time.time()), nonce, raw,
                               path=EVENTS_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 401 and body["error"]["code"] == "SIGNATURE_INVALID",
                f"expected 401 SIGNATURE_INVALID, got {status}: {body}")

    def case_recover_does_not_consume_nonce():
        nonce = _nonce()
        raw = json.dumps(_payload(active.station_id)).encode()
        recover_headers = _headers_for(active, int(time.time()), nonce, raw,
                                       path=RECOVER_PATH)
        status, _ = _post(base_url, raw, recover_headers, path=RECOVER_PATH)
        _expect(status == 404, f"expected 404, got {status}")
        # 恢复查询不得登记 nonce：同一 nonce 随后可正常接纳
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202,
                f"nonce consumed by recover! got {status}: {body}")

    def case_recover_then_replay_still_409():
        """恢复不改写防重放记录：恢复成功后原事件重放仍是 409。"""
        raw, headers, _ = ctx["json"]
        nonce = headers["X-Nonce"]
        recover_headers = _headers_for(active, int(time.time()), nonce, raw,
                                       path=RECOVER_PATH)
        status, _ = _post(base_url, raw, recover_headers, path=RECOVER_PATH)
        _expect(status == 200, f"expected 200, got {status}")
        status, body = _post(base_url, raw, headers)  # 原样重放首个成功请求
        _expect(status == 409 and body["error"]["code"] == "NONCE_REPLAY",
                f"expected 409 NONCE_REPLAY, got {status}: {body}")

    def case_recover_after_concurrent_burst():
        """16 路并发重试只接纳一次：恢复拿到的正是那一次的回执。"""
        raw, nonce = ctx["concurrent"]
        recover_headers = _headers_for(active, int(time.time()), nonce, raw,
                                       path=RECOVER_PATH)
        status, body = _post(base_url, raw, recover_headers, path=RECOVER_PATH)
        _expect(status == 200, f"expected 200, got {status}: {body}")
        expected, _ = stable_digest(json.loads(raw.decode()))
        _expect(body.get("event_digest") == expected,
                "recovered digest mismatch after concurrent burst")

    cases = [
        ("happy_json_202_stable_digest", case_happy_json),
        ("happy_gzip_same_digest", case_happy_gzip_same_digest),
        ("gzip_magic_without_header", case_gzip_magic_without_header),
        ("bad_signature_401", case_bad_signature),
        ("wrong_secret_401", case_wrong_secret),
        ("unknown_key_401", case_unknown_key),
        ("expired_key_403", case_expired_key),
        ("not_yet_valid_key_403", case_not_yet_valid_key),
        ("stale_timestamp_401", case_stale_timestamp),
        ("future_timestamp_401", case_future_timestamp),
        ("malformed_payload_400_then_retry_same_nonce",
         case_malformed_payload_then_retry_same_nonce),
        ("bad_signature_does_not_consume_nonce",
         case_bad_signature_does_not_consume_nonce),
        ("replay_409", case_replay_rejected),
        ("concurrent_replay_exactly_one_wins", case_concurrent_replay_exactly_one_wins),
        ("recover_happy_200", case_recover_happy),
        ("recover_gzip_transport_independent", case_recover_gzip_transport_independent),
        ("recover_unknown_nonce_404", case_recover_unknown_nonce_404),
        ("recover_mismatch_409", case_recover_mismatch_409),
        ("recover_signature_binds_recover_path",
         case_recover_signature_must_bind_recover_path),
        ("recover_does_not_consume_nonce", case_recover_does_not_consume_nonce),
        ("recover_then_replay_still_409", case_recover_then_replay_still_409),
        ("recover_after_concurrent_burst", case_recover_after_concurrent_burst),
    ]

    all_ok = True
    for name, fn in cases:
        try:
            fn()
            print(f"[smoke]   PASS {name}")
        except Exception as exc:  # noqa: BLE001 - 冒烟需要汇总所有失败
            all_ok = False
            print(f"[smoke]   FAIL {name}: {exc}")
    return all_ok
