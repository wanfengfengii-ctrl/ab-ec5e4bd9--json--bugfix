import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.store import (RECEIPT_MISSING, RECEIPT_OK, RECEIPT_UNAVAILABLE, Store)


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "telemetry.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_record_once_then_conflict(self):
        ok = self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0)
        self.assertTrue(ok)
        again = self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 2.0)
        self.assertFalse(again)

    def test_nonce_scoped_per_station(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        # 同一 nonce 值用于不同站点：允许
        self.assertTrue(
            self.store.record_acceptance("st-2", "nonce-1", "k2", "e" * 64, "{}", 1.0))

    def test_conflict_rolls_back_event_row(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        self.assertFalse(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "f" * 64, "{}", 2.0))
        # 冲突事务整体回滚：新摘要不应入库
        row = self.store._conn.execute(
            "SELECT COUNT(*) FROM events WHERE digest = ?", ("f" * 64,)).fetchone()
        self.assertEqual(row[0], 0)

    def test_persistence_across_restart(self):
        """关闭并重开数据库（等价于服务重启）后 nonce 仍被拒绝。"""
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        self.store.close()
        reopened = Store(self.db)
        try:
            self.assertTrue(reopened.nonce_seen("st-1", "nonce-1"))
            self.assertFalse(reopened.record_acceptance(
                "st-1", "nonce-1", "k1", "d" * 64, "{}", 2.0))
        finally:
            reopened.close()
        # 重新打开 self.store 供 tearDown 关闭
        self.store = Store(self.db)

    def test_concurrent_same_nonce_exactly_one_wins(self):
        results = []
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            results.append(self.store.record_acceptance(
                "st-1", "nonce-race", "k1", "d" * 64, "{}", 1.0))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        self.assertEqual(len(results), 16)
        self.assertEqual(sum(1 for r in results if r), 1)
        self.assertEqual(sum(1 for r in results if not r), 15)

    # ---------- 恢复回执 ----------
    def test_receipt_recorded_on_acceptance(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.5))
        state, receipt = self.store.lookup_receipt("st-1", "nonce-1")
        self.assertEqual(state, RECEIPT_OK)
        self.assertEqual(receipt.digest, "d" * 64)
        self.assertEqual(receipt.received_at, 1.5)

    def test_lookup_missing_nonce(self):
        state, receipt = self.store.lookup_receipt("st-1", "never-seen")
        self.assertEqual(state, RECEIPT_MISSING)
        self.assertIsNone(receipt)

    def test_lookup_scoped_per_station(self):
        """回执按站点隔离：他站查询同一 nonce 只能得到 MISSING，不泄露结果。"""
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        state, receipt = self.store.lookup_receipt("st-2", "nonce-1")
        self.assertEqual(state, RECEIPT_MISSING)
        self.assertIsNone(receipt)

    def test_lookup_unavailable_for_legacy_nonce(self):
        """旧数据卷：nonces 表有防重放记录但无回执 -> RECEIPT_UNAVAILABLE。"""
        self.store._conn.execute(
            "INSERT INTO nonces (station_id, nonce, key_id, used_at)"
            " VALUES ('st-1', 'legacy-nonce', 'k1', 1.0)")
        self.store._conn.commit()
        state, receipt = self.store.lookup_receipt("st-1", "legacy-nonce")
        self.assertEqual(state, RECEIPT_UNAVAILABLE)
        self.assertIsNone(receipt)
        # 防重放语义不受恢复查询影响
        self.assertTrue(self.store.nonce_seen("st-1", "legacy-nonce"))

    def test_lookup_is_read_only(self):
        """恢复查询不登记 nonce：查询失败后该 nonce 仍可用于接纳。"""
        self.assertEqual(self.store.lookup_receipt("st-1", "nonce-x")[0],
                         RECEIPT_MISSING)
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-x", "k1", "d" * 64, "{}", 1.0))

    def test_conflict_keeps_original_receipt(self):
        """重放冲突整体回滚：回执仍指向首次接纳的摘要与时刻。"""
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        self.assertFalse(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "f" * 64, "{}", 2.0))
        state, receipt = self.store.lookup_receipt("st-1", "nonce-1")
        self.assertEqual(state, RECEIPT_OK)
        self.assertEqual(receipt.digest, "d" * 64)
        self.assertEqual(receipt.received_at, 1.0)

    def test_receipt_survives_restart(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.5))
        self.store.close()
        reopened = Store(self.db)
        try:
            state, receipt = reopened.lookup_receipt("st-1", "nonce-1")
            self.assertEqual(state, RECEIPT_OK)
            self.assertEqual(receipt.digest, "d" * 64)
            self.assertEqual(receipt.received_at, 1.5)
        finally:
            reopened.close()
        self.store = Store(self.db)


if __name__ == "__main__":
    unittest.main()
