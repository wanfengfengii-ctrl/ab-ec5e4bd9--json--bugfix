import gzip
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.errors import ApiError
from app.payload import (maybe_decompress, parse_and_validate, stable_digest)

LIMIT = 1024 * 1024


def _valid_payload(station="st-1"):
    return {
        "station_id": station,
        "events": [{"event_id": "evt-1", "measured_at": int(time.time()),
                    "dose_usv_h": 0.12}],
    }


class DecompressTest(unittest.TestCase):
    def test_plain_json_passthrough(self):
        raw = b'{"a":1}'
        self.assertEqual(maybe_decompress(raw, None, LIMIT), raw)
        self.assertEqual(maybe_decompress(raw, "identity", LIMIT), raw)

    def test_gzip_with_header(self):
        raw = gzip.compress(b'{"a":1}')
        self.assertEqual(maybe_decompress(raw, "gzip", LIMIT), b'{"a":1}')

    def test_gzip_magic_sniffed_without_header(self):
        raw = gzip.compress(b'{"a":1}')
        self.assertEqual(maybe_decompress(raw, None, LIMIT), b'{"a":1}')

    def test_unsupported_encoding(self):
        with self.assertRaises(ApiError) as ctx:
            maybe_decompress(b"abc", "br", LIMIT)
        self.assertEqual(ctx.exception.status, 415)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ENCODING")

    def test_gzip_header_but_plain_body(self):
        with self.assertRaises(ApiError) as ctx:
            maybe_decompress(b'{"a":1}', "gzip", LIMIT)
        self.assertEqual(ctx.exception.code, "PAYLOAD_MALFORMED")

    def test_truncated_gzip(self):
        raw = gzip.compress(b"x" * 1000)[:8]
        with self.assertRaises(ApiError) as ctx:
            maybe_decompress(raw, "gzip", LIMIT)
        self.assertEqual(ctx.exception.code, "PAYLOAD_MALFORMED")

    def test_decompressed_size_limit(self):
        raw = gzip.compress(b"x" * 10000)
        with self.assertRaises(ApiError) as ctx:
            maybe_decompress(raw, "gzip", 100)
        self.assertEqual(ctx.exception.status, 413)


class ValidateTest(unittest.TestCase):
    def setUp(self):
        self.now = time.time()

    def _roundtrip(self, obj, station="st-1"):
        return parse_and_validate(json.dumps(obj).encode(), station, self.now)

    def test_valid_payload(self):
        obj = self._roundtrip(_valid_payload())
        self.assertEqual(obj["station_id"], "st-1")

    def test_invalid_json(self):
        with self.assertRaises(ApiError) as ctx:
            parse_and_validate(b'{"station_id": ', "st-1", self.now)
        self.assertEqual(ctx.exception.code, "PAYLOAD_MALFORMED")

    def test_non_object_json(self):
        with self.assertRaises(ApiError):
            parse_and_validate(b"[1,2,3]", "st-1", self.now)

    def test_station_mismatch(self):
        with self.assertRaises(ApiError) as ctx:
            self._roundtrip(_valid_payload("st-1"), station="st-2")
        self.assertEqual(ctx.exception.code, "PAYLOAD_MALFORMED")

    def test_empty_events(self):
        obj = _valid_payload()
        obj["events"] = []
        with self.assertRaises(ApiError):
            self._roundtrip(obj)

    def test_bad_event_fields(self):
        for bad in (
            {"event_id": "", "measured_at": self.now, "dose_usv_h": 0.1},
            {"event_id": "e", "measured_at": True, "dose_usv_h": 0.1},
            {"event_id": "e", "measured_at": "just-now", "dose_usv_h": 0.1},
            {"event_id": "e", "measured_at": self.now, "dose_usv_h": -1},
            {"event_id": "e", "measured_at": self.now, "dose_usv_h": "high"},
        ):
            with self.assertRaises(ApiError, msg=f"should reject {bad}"):
                self._roundtrip({"station_id": "st-1", "events": [bad]})


class DigestTest(unittest.TestCase):
    def test_digest_stable_across_key_order_and_whitespace(self):
        a = json.dumps({"b": 2, "a": 1, "station_id": "st-1",
                        "events": [{"event_id": "e", "measured_at": 1,
                                    "dose_usv_h": 0.5}]})
        b = '{ "station_id" : "st-1", "a":1, "events":[{"dose_usv_h":0.5,' \
            '"measured_at":1,"event_id":"e"}], "b":2 }'
        digest_a, _ = stable_digest(json.loads(a))
        digest_b, _ = stable_digest(json.loads(b))
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(len(digest_a), 64)

    def test_digest_changes_with_content(self):
        d1, _ = stable_digest({"a": 1})
        d2, _ = stable_digest({"a": 2})
        self.assertNotEqual(d1, d2)

    def test_digest_equal_json_numbers_int_and_float(self):
        """数值相等的 JSON 数字（1 与 1.0）仅文本表示不同，摘要必须一致。"""
        for a, b in (
            (1, 1.0), (1.0, 1), (0, 0.0), (100, 1.0e2),
            (-5, -5.0), (1.5, 1.50), (0.117, 0.1170),
        ):
            da, _ = stable_digest({"dose_usv_h": a})
            db, _ = stable_digest({"dose_usv_h": b})
            self.assertEqual(da, db, f"{a!r} 与 {b!r} 数值相等却摘要不同")

    def test_digest_distinguishes_different_numbers(self):
        for a, b in ((1, 2), (1.0, 1.0000001), (0.1, 0.2), (1, -1)):
            da, _ = stable_digest({"dose_usv_h": a})
            db, _ = stable_digest({"dose_usv_h": b})
            self.assertNotEqual(da, db, f"{a!r} 与 {b!r} 数值不同却摘要相同")

    def test_digest_keeps_large_integers_exact(self):
        """超过 2^53 的大整数不做浮点归并，两个不同整数不得碰撞。"""
        d1, _ = stable_digest({"x": 9007199254740993})
        d2, _ = stable_digest({"x": 9007199254740992})
        self.assertNotEqual(d1, d2)
        d3, _ = stable_digest({"x": 99999999999999999999998})
        d4, _ = stable_digest({"x": 99999999999999999999999})
        self.assertNotEqual(d3, d4)

    def test_digest_bool_not_treated_as_number(self):
        """布尔值不参与数字归并，保持自身表示。"""
        d_true, c = stable_digest({"flag": True})
        d_one, _ = stable_digest({"flag": 1})
        self.assertNotEqual(d_true, d_one)
        self.assertIn("true", c)


if __name__ == "__main__":
    unittest.main()
