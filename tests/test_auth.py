import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth


class CanonicalStringTest(unittest.TestCase):
    def test_golden_vector(self):
        """规范化串必须与文档约定逐字节一致（互操作金标准）。"""
        raw = b'{"a":1}'
        expected_hash = hashlib.sha256(raw).hexdigest()
        cs = auth.canonical_string(
            "POST", "/api/telemetry/events",
            "station-alpha", "test-key-1", "1759670000", "nonce-abc-1", raw)
        self.assertEqual(
            cs,
            "POST\n/api/telemetry/events\nstation-alpha\ntest-key-1\n"
            f"1759670000\nnonce-abc-1\n{expected_hash}")

    def test_body_hash_covers_raw_bytes(self):
        self.assertEqual(auth.body_sha256_hex(b""),
                         hashlib.sha256(b"").hexdigest())
        self.assertNotEqual(auth.body_sha256_hex(b"a"), auth.body_sha256_hex(b"b"))


class SignVerifyTest(unittest.TestCase):
    def setUp(self):
        self.raw = b'{"station_id":"station-alpha","events":[]}'
        self.canonical = auth.canonical_string(
            "POST", "/api/telemetry/events",
            "station-alpha", "test-key-1", "1759670000", "nonce-xyz-9", self.raw)

    def test_roundtrip(self):
        sig = auth.sign("secret-1", self.canonical)
        self.assertTrue(auth.verify_signature("secret-1", self.canonical, sig))

    def test_sign_request_helper_matches(self):
        sig = auth.sign_request("secret-1", "POST", "/api/telemetry/events",
                                "station-alpha", "test-key-1", "1759670000",
                                "nonce-xyz-9", self.raw)
        self.assertTrue(auth.verify_signature("secret-1", self.canonical, sig))

    def test_wrong_secret_rejected(self):
        sig = auth.sign("secret-1", self.canonical)
        self.assertFalse(auth.verify_signature("secret-2", self.canonical, sig))

    def test_tampered_signature_rejected(self):
        sig = auth.sign("secret-1", self.canonical)
        tampered = ("A" if sig[0] != "A" else "B") + sig[1:]
        self.assertFalse(auth.verify_signature("secret-1", self.canonical, tampered))

    def test_tampered_canonical_rejected(self):
        sig = auth.sign("secret-1", self.canonical)
        other = auth.canonical_string(
            "POST", "/api/telemetry/events",
            "station-alpha", "test-key-1", "1759670001", "nonce-xyz-9", self.raw)
        self.assertFalse(auth.verify_signature("secret-1", other, sig))

    def test_invalid_base64_rejected(self):
        self.assertFalse(auth.verify_signature("secret-1", self.canonical,
                                               "!!!not-base64!!!"))


if __name__ == "__main__":
    unittest.main()
