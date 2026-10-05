import gzip
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.errors import ApiError
from app.payload import (canonical_payloads_equal, maybe_decompress,
                         parse_and_validate, semantic_equal, stable_digest)

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

    def test_digest_same_for_integer_and_equal_float(self):
        """JSON 的 1 与 1.0 数值相等：规范化文本与摘要必须一致（双向）。"""
        d_int, c_int = stable_digest(json.loads('{"a": 1}'))
        d_float, c_float = stable_digest(json.loads('{"a": 1.0}'))
        self.assertEqual(c_int, c_float)
        self.assertEqual(d_int, d_float)
        # 嵌套在事件字段里同样归一
        payload_int = json.loads(
            '{"station_id": "st-1",'
            ' "events": [{"event_id": "e", "measured_at": 100,'
            '             "dose_usv_h": 1}]}')
        payload_float = json.loads(
            '{"station_id": "st-1",'
            ' "events": [{"event_id": "e", "measured_at": 100.0,'
            '             "dose_usv_h": 1.0}]}')
        self.assertEqual(stable_digest(payload_int)[0],
                         stable_digest(payload_float)[0])

    def test_digest_zero_and_negative_zero(self):
        self.assertEqual(stable_digest({"a": 0})[0],
                         stable_digest({"a": -0.0})[0])

    def test_digest_distinguishes_bool_from_number(self):
        """布尔不是数值：true 不得与 1 并为同一摘要。"""
        self.assertNotEqual(stable_digest({"a": True})[0],
                            stable_digest({"a": 1})[0])

    def test_digest_distinguishes_close_but_unequal_floats(self):
        self.assertNotEqual(stable_digest({"a": 1})[0],
                            stable_digest({"a": 1.5})[0])

    def test_digest_big_integer_precision_preserved(self):
        """超过 float 精确整数范围的大整数保留原值，不被错误归一。"""
        big = 10 ** 30
        d1, _ = stable_digest({"a": big})
        d2, _ = stable_digest({"a": big + 1})
        self.assertNotEqual(d1, d2)


class SemanticEqualTest(unittest.TestCase):
    def test_number_representations_equal(self):
        self.assertTrue(semantic_equal(1, 1.0))
        self.assertTrue(semantic_equal(1.0, 1))
        self.assertTrue(semantic_equal(0, -0.0))
        self.assertFalse(semantic_equal(1, 1.5))
        self.assertFalse(semantic_equal(1, 2))

    def test_bool_distinct_from_number(self):
        self.assertFalse(semantic_equal(True, 1))
        self.assertFalse(semantic_equal(False, 0))
        self.assertTrue(semantic_equal(True, True))
        self.assertTrue(semantic_equal(False, False))

    def test_string_and_none_not_coerced(self):
        self.assertFalse(semantic_equal("1", 1))
        self.assertFalse(semantic_equal(None, 0))
        self.assertTrue(semantic_equal("x", "x"))
        self.assertTrue(semantic_equal(None, None))

    def test_nested_structures(self):
        a = {"k": [1, {"x": 2}], "s": "v"}
        b = {"k": [1.0, {"x": 2.0}], "s": "v"}
        self.assertTrue(semantic_equal(a, b))
        self.assertFalse(semantic_equal(a, {"k": [1.0, {"x": 2.5}], "s": "v"}))
        self.assertFalse(semantic_equal({"k": 1}, {"k": 1, "extra": 2}))
        self.assertFalse(semantic_equal([1, 2], [1, 2, 3]))
        self.assertTrue(semantic_equal([], []))

    def test_canonical_payloads_equal_via_json(self):
        from app.payload import canonical_json
        c_int = canonical_json({"a": 1, "b": [2, 3]})
        c_float = canonical_json({"a": 1.0, "b": [2.0, 3.0]})
        self.assertTrue(canonical_payloads_equal(c_int, c_float))
        self.assertFalse(canonical_payloads_equal(
            canonical_json({"a": 1}), canonical_json({"a": 2})))
        # 旧版（无数值归一）保存的整数文本规范化载荷也能识别
        legacy = json.dumps({"a": 1, "b": [2, 3]}, sort_keys=True,
                            separators=(",", ":"))
        self.assertTrue(canonical_payloads_equal(legacy, c_float))


if __name__ == "__main__":
    unittest.main()
