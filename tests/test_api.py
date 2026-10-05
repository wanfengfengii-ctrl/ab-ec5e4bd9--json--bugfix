"""端到端测试：真实 HTTP 服务器 + 临时密钥库 + 临时数据目录。"""
import gzip
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth
from app.config import Config
from app.payload import stable_digest
from app.server import create_server

EVENTS_PATH = "/api/telemetry/events"
RECOVER_PATH = "/api/telemetry/events/recover"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def _write_keys(path: str) -> dict:
    now = time.time()
    keys = {
        "active": {"key_id": "k-active", "station_id": "st-1",
                   "secret": "secret-active",
                   "not_before": _iso(now - 3600), "not_after": _iso(now + 3600)},
        "expired": {"key_id": "k-expired", "station_id": "st-1",
                    "secret": "secret-expired",
                    "not_before": _iso(now - 7200), "not_after": _iso(now - 3600)},
        "future": {"key_id": "k-future", "station_id": "st-1",
                   "secret": "secret-future",
                   "not_before": _iso(now + 3600), "not_after": _iso(now + 7200)},
        "other": {"key_id": "k-other", "station_id": "st-2",
                  "secret": "secret-other",
                  "not_before": _iso(now - 3600), "not_after": _iso(now + 3600)},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"keys": list(keys.values())}, fh)
    return keys


class ServerFixture:
    def __init__(self, data_dir: str, keys_file: str):
        config = Config(host="127.0.0.1", port=0, keys_file=keys_file,
                        data_dir=data_dir)
        self.httpd = create_server(config)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd.gateway.store.close()
        self.thread.join(timeout=5)


def post(url: str, raw: bytes, headers: dict,
         path: str = EVENTS_PATH) -> tuple[int, dict]:
    req = urllib.request.Request(url + path, data=raw,
                                 headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def get(url: str, path: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url + path, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def signed_headers(key: dict, timestamp: int, nonce: str, raw: bytes,
                   station: str | None = None, secret: str | None = None,
                   path: str = EVENTS_PATH) -> dict:
    station = station or key["station_id"]
    signature = auth.sign_request(secret or key["secret"], "POST", path,
                                  station, key["key_id"], str(timestamp), nonce, raw)
    return {
        "X-Station-Id": station,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def make_payload(station: str) -> dict:
    return {
        "station_id": station,
        "sent_at": int(time.time()),
        "events": [
            {"event_id": "evt-" + secrets.token_hex(4),
             "measured_at": int(time.time()) - 5,
             "dose_usv_h": 0.117, "instrument": "gm-1"},
        ],
    }


def tamper_signature(sig: str) -> str:
    """保证篡改后的签名与原文不同（首字符换成另一个 Base64 字符）。"""
    return ("A" if sig[0] != "A" else "B") + sig[1:]


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys_file = os.path.join(self.tmp.name, "keys.json")
        self.keys = _write_keys(self.keys_file)
        self.data_dir = os.path.join(self.tmp.name, "data")
        self.server = ServerFixture(self.data_dir, self.keys_file)
        self.key = self.keys["active"]

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def _nonce(self) -> str:
        return secrets.token_hex(12)

    def _send_valid(self, payload: dict | None = None, nonce: str | None = None):
        payload = payload if payload is not None else make_payload("st-1")
        raw = json.dumps(payload).encode()
        nonce = nonce or self._nonce()
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        return post(self.server.url, raw, headers), raw, headers, payload

    # ---------- 健康检查 ----------
    def test_healthz(self):
        status, body = get(self.server.url, "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    # ---------- 成功路径 ----------
    def test_accept_json_202_with_stable_digest(self):
        (status, body), _, _, payload = self._send_valid()
        self.assertEqual(status, 202)
        self.assertEqual(body["status"], "accepted")
        expected, _ = stable_digest(payload)
        self.assertEqual(body["event_digest"], expected)

    def test_accept_gzip_same_digest(self):
        payload = make_payload("st-1")
        plain = json.dumps(payload).encode()
        compressed = gzip.compress(plain)
        headers = signed_headers(self.key, int(time.time()), self._nonce(),
                                 compressed)
        headers["Content-Encoding"] = "gzip"
        status, body = post(self.server.url, compressed, headers)
        self.assertEqual(status, 202)
        expected, _ = stable_digest(payload)
        self.assertEqual(body["event_digest"], expected)

    def test_gzip_without_content_encoding_sniffed(self):
        payload = make_payload("st-1")
        compressed = gzip.compress(json.dumps(payload).encode())
        headers = signed_headers(self.key, int(time.time()), self._nonce(),
                                 compressed)
        status, _ = post(self.server.url, compressed, headers)
        self.assertEqual(status, 202)

    # ---------- 签名 ----------
    def test_bad_signature_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        headers["X-Signature"] = tamper_signature(headers["X-Signature"])
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "SIGNATURE_INVALID")

    def test_wrong_secret_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw,
                                 secret="not-the-secret")
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "SIGNATURE_INVALID")

    def test_unknown_key_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        headers["X-Key-Id"] = "no-such-key"
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "KEY_UNKNOWN")

    # ---------- 密钥有效期 ----------
    def test_expired_key_403(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.keys["expired"], int(time.time()),
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_EXPIRED")

    def test_not_yet_valid_key_403(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.keys["future"], int(time.time()),
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_EXPIRED")

    def test_key_station_mismatch_403(self):
        raw = json.dumps(make_payload("st-2")).encode()
        # k-other 属于 st-2，却用于 st-1 的报文头
        headers = signed_headers(self.keys["other"], int(time.time()),
                                 self._nonce(), raw, station="st-1")
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_STATION_MISMATCH")

    # ---------- 时间窗 ----------
    def test_stale_timestamp_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()) - 3600,
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "TIMESTAMP_OUT_OF_RANGE")

    def test_future_timestamp_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()) + 3600,
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "TIMESTAMP_OUT_OF_RANGE")

    # ---------- 畸形载荷 ----------
    def test_malformed_payload_400(self):
        raw = b'{"station_id": "st-1", "events": ['
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "PAYLOAD_MALFORMED")

    def test_payload_station_mismatch_400(self):
        raw = json.dumps(make_payload("st-2")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "PAYLOAD_MALFORMED")

    # ---------- 失败不占用 nonce ----------
    def test_failed_request_does_not_consume_nonce(self):
        nonce = self._nonce()
        # 1) 签名错误 -> 401
        raw = json.dumps(make_payload("st-1")).encode()
        bad = signed_headers(self.key, int(time.time()), nonce, raw)
        bad["X-Signature"] = tamper_signature(bad["X-Signature"])
        status, _ = post(self.server.url, raw, bad)
        self.assertEqual(status, 401)
        # 2) 同一 nonce 修正签名后 -> 202
        good = signed_headers(self.key, int(time.time()), nonce, raw)
        status, _ = post(self.server.url, raw, good)
        self.assertEqual(status, 202)

    def test_malformed_payload_does_not_consume_nonce(self):
        nonce = self._nonce()
        bad_raw = b'{"station_id": "st-1", broken'
        headers = signed_headers(self.key, int(time.time()), nonce, bad_raw)
        status, _ = post(self.server.url, bad_raw, headers)
        self.assertEqual(status, 400)
        # 同一 nonce 换上合法载荷 -> 202
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, _ = post(self.server.url, raw, headers)
        self.assertEqual(status, 202)

    # ---------- 防重放 ----------
    def test_replay_409(self):
        (status, _), raw, headers, _ = self._send_valid()
        self.assertEqual(status, 202)
        status, body = post(self.server.url, raw, headers)  # 原样重放
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "NONCE_REPLAY")

    def test_replay_survives_restart(self):
        (status, _), raw, headers, _ = self._send_valid()
        self.assertEqual(status, 202)
        # 重启服务（同一数据目录）
        self.server.stop()
        self.server = ServerFixture(self.data_dir, self.keys_file)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "NONCE_REPLAY")

    def test_concurrent_same_nonce_exactly_one_accepted(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            return post(self.server.url, raw, headers)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: worker(), range(16)))
        codes = [s for s, _ in results]
        self.assertEqual(codes.count(202), 1, f"codes={codes}")
        self.assertEqual(codes.count(409), 15, f"codes={codes}")

    # ---------- 其他 ----------
    def test_missing_headers_400(self):
        status, body = post(self.server.url, b"{}", {})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "MALFORMED_HEADERS")

    def test_unknown_path_404(self):
        req = urllib.request.Request(self.server.url + "/nope", data=b"{}",
                                     method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)


class RecoverTest(unittest.TestCase):
    """POST /api/telemetry/events/recover：丢失 202 的恢复确认。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys_file = os.path.join(self.tmp.name, "keys.json")
        self.keys = _write_keys(self.keys_file)
        self.data_dir = os.path.join(self.tmp.name, "data")
        self.server = ServerFixture(self.data_dir, self.keys_file)
        self.key = self.keys["active"]

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def _nonce(self) -> str:
        return secrets.token_hex(12)

    def _accept(self, payload: dict | None = None, nonce: str | None = None,
                raw: bytes | None = None):
        """接纳一个事件，返回 (响应状态, 响应体, 原始字节, nonce, 载荷)。"""
        payload = payload if payload is not None else make_payload("st-1")
        raw = raw if raw is not None else json.dumps(payload).encode()
        nonce = nonce or self._nonce()
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 202, f"accept failed: {body}")
        return body, raw, nonce, payload

    def _recover(self, raw: bytes, nonce: str, key: dict | None = None,
                 station: str | None = None, path: str = RECOVER_PATH,
                 extra_headers: dict | None = None):
        key = key or self.key
        headers = signed_headers(key, int(time.time()), nonce, raw,
                                 station=station, path=path)
        if extra_headers:
            headers.update(extra_headers)
        return post(self.server.url, raw, headers, path=RECOVER_PATH)

    # ---------- 成功恢复 ----------
    def test_recover_returns_original_receipt(self):
        accepted, raw, nonce, payload = self._accept()
        status, body = self._recover(raw, nonce)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "recovered")
        self.assertEqual(body["station_id"], "st-1")
        self.assertEqual(body["nonce"], nonce)
        self.assertEqual(body["event_digest"], accepted["event_digest"])
        self.assertEqual(body["received_at"], accepted["received_at"])
        expected, _ = stable_digest(payload)
        self.assertEqual(body["event_digest"], expected)

    def test_recover_gzip_accepted_plain_recovered(self):
        """gzip 接纳、明文恢复：稳定摘要与传输编码无关。"""
        payload = make_payload("st-1")
        compressed = gzip.compress(json.dumps(payload).encode())
        nonce = self._nonce()
        headers = signed_headers(self.key, int(time.time()), nonce, compressed)
        headers["Content-Encoding"] = "gzip"
        status, accepted = post(self.server.url, compressed, headers)
        self.assertEqual(status, 202)

        plain = json.dumps(payload).encode()
        status, body = self._recover(plain, nonce)
        self.assertEqual(status, 200)
        self.assertEqual(body["event_digest"], accepted["event_digest"])
        self.assertEqual(body["received_at"], accepted["received_at"])

    def test_recover_gzip_request(self):
        accepted, raw, nonce, _ = self._accept()
        compressed = gzip.compress(raw)
        status, body = self._recover(compressed, nonce,
                                     extra_headers={"Content-Encoding": "gzip"})
        self.assertEqual(status, 200)
        self.assertEqual(body["event_digest"], accepted["event_digest"])

    # ---------- 失败路径 ----------
    def test_recover_unknown_nonce_404(self):
        raw = json.dumps(make_payload("st-1")).encode()
        status, body = self._recover(raw, self._nonce())
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "RECEIPT_NOT_FOUND")

    # ---------- 等值 JSON 数字表示 ----------
    def _fixed_event_raw(self, dose_text: str) -> bytes:
        """构造 dose_usv_h 数字文本可控的载荷（用于区分 1 / 1.0 / 1.0e2）。"""
        return (
            b'{"station_id":"st-1","events":[{"event_id":"evt-fixed",'
            b'"measured_at":1700000000,"dose_usv_h":' + dose_text.encode() + b"}]}")

    def _accept_raw(self, raw: bytes, nonce: str):
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 202, f"accept failed: {body}")
        return body

    def test_recover_int_then_equivalent_float(self):
        """接纳 dose=1（整数），恢复 dose=1.0（等值浮点）-> 200 且回执原样。"""
        nonce = self._nonce()
        accepted = self._accept_raw(self._fixed_event_raw("1"), nonce)
        status, body = self._recover(self._fixed_event_raw("1.0"), nonce)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "recovered")
        self.assertEqual(body["event_digest"], accepted["event_digest"])
        self.assertEqual(body["received_at"], accepted["received_at"])

    def test_recover_float_then_equivalent_int(self):
        """反向：接纳 dose=1.0，恢复 dose=1 -> 200。"""
        nonce = self._nonce()
        accepted = self._accept_raw(self._fixed_event_raw("1.0"), nonce)
        status, body = self._recover(self._fixed_event_raw("1"), nonce)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["event_digest"], accepted["event_digest"])
        self.assertEqual(body["received_at"], accepted["received_at"])

    def test_recover_equivalent_exponent_notation(self):
        """100 与 1.0e2 文本不同但数值相等 -> 200。"""
        nonce = self._nonce()
        accepted = self._accept_raw(self._fixed_event_raw("100"), nonce)
        status, body = self._recover(self._fixed_event_raw("1.0e2"), nonce)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["event_digest"], accepted["event_digest"])

    def test_recover_changed_value_still_409(self):
        """剂量数值确实发生变化 -> 409 RECEIPT_MISMATCH。"""
        nonce = self._nonce()
        self._accept_raw(self._fixed_event_raw("1"), nonce)
        status, body = self._recover(self._fixed_event_raw("2"), nonce)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "RECEIPT_MISMATCH")

    def test_recover_close_but_unequal_value_409(self):
        nonce = self._nonce()
        self._accept_raw(self._fixed_event_raw("1"), nonce)
        status, body = self._recover(self._fixed_event_raw("1.0000001"), nonce)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "RECEIPT_MISMATCH")

    def test_recover_numeric_equivalence_in_measured_at(self):
        """measured_at 的 1 与 1.0 同属数字表示差异 -> 200。"""
        nonce = self._nonce()
        raw = (b'{"station_id":"st-1","events":[{"event_id":"e",'
               b'"measured_at":1700000000,"dose_usv_h":1}]}')
        accepted = self._accept_raw(raw, nonce)
        rec = (b'{"station_id":"st-1","events":[{"event_id":"e",'
               b'"measured_at":1700000000.0,"dose_usv_h":1.0}]}')
        status, body = self._recover(rec, nonce)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["event_digest"], accepted["event_digest"])

    def test_recover_legacy_volume_old_digest_format(self):
        """升级前数据卷的旧格式回执（未做数字归一化）也能按数值语义恢复。"""
        import hashlib
        import sqlite3
        from app.payload import canonical_json

        nonce = self._nonce()
        obj = json.loads(self._fixed_event_raw("1.0"))
        # 旧版本：直接对解析结果规范化 JSON 求摘要，1.0 保留为 "1.0"
        legacy_canonical = canonical_json(obj)
        legacy_digest = hashlib.sha256(
            legacy_canonical.encode("utf-8")).hexdigest()
        received = time.time()
        self.server.stop()
        conn = sqlite3.connect(os.path.join(self.data_dir, "telemetry.db"))
        conn.execute(
            "INSERT INTO nonces (station_id, nonce, key_id, used_at)"
            " VALUES (?, ?, ?, ?)", ("st-1", nonce, self.key["key_id"], received))
        conn.execute(
            "INSERT INTO events (digest, station_id, payload, received_at)"
            " VALUES (?, ?, ?, ?)",
            (legacy_digest, "st-1", legacy_canonical, received))
        conn.execute(
            "INSERT INTO receipts (station_id, nonce, digest, received_at)"
            " VALUES (?, ?, ?, ?)", ("st-1", nonce, legacy_digest, received))
        conn.commit()
        conn.close()
        self.server = ServerFixture(self.data_dir, self.keys_file)

        # 用整数 1 恢复旧回执（1.0）-> 200，且原样返回首次回执
        status, body = self._recover(self._fixed_event_raw("1"), nonce)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "recovered")
        self.assertEqual(body["event_digest"], legacy_digest)
        self.assertEqual(body["received_at"], int(received))

        # 数值确实不同仍 409
        status, body = self._recover(self._fixed_event_raw("2"), nonce)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "RECEIPT_MISMATCH")

    def test_recover_mismatch_409(self):
        _, _, nonce, _ = self._accept()
        other = json.dumps(make_payload("st-1")).encode()  # 同站点不同内容
        status, body = self._recover(other, nonce)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "RECEIPT_MISMATCH")

    def test_recover_legacy_volume_409_unavailable(self):
        """旧数据卷：仅有防重放记录、无回执 -> 409 RECEIPT_UNAVAILABLE。"""
        _, raw, nonce, _ = self._accept()
        # 模拟旧版本写入的数据卷：删掉回执表内容，仅保留 nonces 防重放记录
        self.server.stop()
        import sqlite3
        conn = sqlite3.connect(os.path.join(self.data_dir, "telemetry.db"))
        conn.execute("DROP TABLE receipts")
        conn.commit()
        conn.close()
        self.server = ServerFixture(self.data_dir, self.keys_file)

        status, body = self._recover(raw, nonce)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "RECEIPT_UNAVAILABLE")
        # 防重放语义在旧卷上依然成立
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "NONCE_REPLAY")

    def test_recover_signature_must_bind_recover_path(self):
        """沿用事件路径的签名在恢复路径上必须失败（路径参与规范化串）。"""
        _, raw, nonce, _ = self._accept()
        headers = signed_headers(self.key, int(time.time()), nonce, raw,
                                 path=EVENTS_PATH)
        status, body = post(self.server.url, raw, headers, path=RECOVER_PATH)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "SIGNATURE_INVALID")

    def test_recover_bad_signature_401(self):
        _, raw, nonce, _ = self._accept()
        headers = signed_headers(self.key, int(time.time()), nonce, raw,
                                 path=RECOVER_PATH)
        headers["X-Signature"] = tamper_signature(headers["X-Signature"])
        status, body = post(self.server.url, raw, headers, path=RECOVER_PATH)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "SIGNATURE_INVALID")

    def test_recover_stale_timestamp_401(self):
        _, raw, nonce, _ = self._accept()
        headers = signed_headers(self.key, int(time.time()) - 3600, nonce, raw,
                                 path=RECOVER_PATH)
        status, body = post(self.server.url, raw, headers, path=RECOVER_PATH)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "TIMESTAMP_OUT_OF_RANGE")

    def test_recover_expired_key_403(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.keys["expired"], int(time.time()),
                                 self._nonce(), raw, path=RECOVER_PATH)
        status, body = post(self.server.url, raw, headers, path=RECOVER_PATH)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_EXPIRED")

    # ---------- 不泄露他站结果 ----------
    def test_recover_other_station_gets_404(self):
        """st-2 用自己的密钥查询 st-1 的 nonce：只能得到 404，不泄露任何结果。"""
        _, _, nonce, _ = self._accept()
        raw = json.dumps(make_payload("st-2")).encode()
        status, body = self._recover(raw, nonce, key=self.keys["other"])
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "RECEIPT_NOT_FOUND")

    def test_recover_with_other_stations_key_rejected(self):
        """持 st-2 密钥冒用 st-1 站点头：密钥站点绑定检查先行拒绝。"""
        _, raw, nonce, _ = self._accept()
        status, body = self._recover(raw, nonce, key=self.keys["other"],
                                     station="st-1")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_STATION_MISMATCH")

    # ---------- 恢复不登记、不改写 nonce ----------
    def test_recover_does_not_register_nonce(self):
        nonce = self._nonce()
        raw = json.dumps(make_payload("st-1")).encode()
        status, _ = self._recover(raw, nonce)
        self.assertEqual(status, 404)
        # 恢复查询不得占用 nonce：同一 nonce 随后可正常接纳
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 202, f"nonce consumed by recover! {body}")

    def test_recover_does_not_modify_receipt(self):
        accepted, raw, nonce, _ = self._accept()
        for _ in range(3):
            status, body = self._recover(raw, nonce)
            self.assertEqual(status, 200)
            self.assertEqual(body["received_at"], accepted["received_at"])
        # 恢复之后原事件重放仍被拒绝（防重放记录未被改写）
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "NONCE_REPLAY")

    # ---------- 重启与并发 ----------
    def test_recover_survives_restart(self):
        accepted, raw, nonce, _ = self._accept()
        self.server.stop()
        self.server = ServerFixture(self.data_dir, self.keys_file)
        status, body = self._recover(raw, nonce)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "recovered")
        self.assertEqual(body["event_digest"], accepted["event_digest"])
        self.assertEqual(body["received_at"], accepted["received_at"])

    def test_concurrent_recover_all_200_and_single_acceptance(self):
        """并发重试：接纳至多一次；恢复查询幂等，全部拿到同一回执。"""
        accepted, raw, nonce, _ = self._accept()
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            return self._recover(raw, nonce)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: worker(), range(16)))
        codes = [s for s, _ in results]
        self.assertEqual(codes.count(200), 16, f"codes={codes}")
        for _, body in results:
            self.assertEqual(body["event_digest"], accepted["event_digest"])
            self.assertEqual(body["received_at"], accepted["received_at"])
        # 并发恢复之后，原事件重放仍是 409：接纳记录始终只有一条
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, _ = post(self.server.url, raw, headers)
        self.assertEqual(status, 409)


if __name__ == "__main__":
    unittest.main()
