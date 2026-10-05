"""SQLite 持久化：nonce 防重放登记、事件摘要存储与接纳回执。

nonce 以 (station_id, nonce) 为主键，只有在请求通过全部校验、即将被接纳时
才在同一事务内插入；任何失败路径都不会写入 nonce。数据库文件落在 DATA_DIR
（Compose 中挂载为命名卷），因此并发请求与服务重启后均满足"至多成功一次"。

receipts 表在接纳的同一事务内记录 (station_id, nonce) -> (digest, received_at)
回执，供 POST /api/telemetry/events/recover 在不再次接纳的前提下还原原 202
结果。旧版本数据卷只有 nonces/events 记录而没有 receipts 行，恢复时据此返回
RECEIPT_UNAVAILABLE，绝不凭空编造接纳结果。
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    station_id TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    used_at    REAL NOT NULL,
    PRIMARY KEY (station_id, nonce)
);
CREATE TABLE IF NOT EXISTS events (
    digest      TEXT PRIMARY KEY,
    station_id  TEXT NOT NULL,
    payload     TEXT NOT NULL,
    received_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    station_id  TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    digest      TEXT NOT NULL,
    received_at REAL NOT NULL,
    PRIMARY KEY (station_id, nonce)
);
"""

# lookup_receipt 的三种结果
RECEIPT_OK = "ok"                # 回执存在，可核对事件摘要
RECEIPT_MISSING = "missing"      # 该站点从未登记此 nonce
RECEIPT_UNAVAILABLE = "unavailable"  # 仅有旧版防重放记录，无回执内容可还原


@dataclass(frozen=True)
class Receipt:
    """一次接纳留存的回执：稳定事件摘要与首次接纳时刻（Unix 秒）。"""
    digest: str
    received_at: float


class Store:
    """单连接 + 互斥锁：写操作串行化，配合主键约束保证并发下 nonce 至多成功一次。"""

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def record_acceptance(self, station_id: str, nonce: str, key_id: str,
                          digest: str, canonical_payload: str, now: float) -> bool:
        """同一事务内登记 nonce、事件摘要与恢复回执。

        返回 True 表示接纳成功；nonce 冲突返回 False，且事务回滚不留任何记录。
        """
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO nonces (station_id, nonce, key_id, used_at)"
                    " VALUES (?, ?, ?, ?)",
                    (station_id, nonce, key_id, now),
                )
                self._conn.execute(
                    "INSERT OR IGNORE INTO events (digest, station_id, payload, received_at)"
                    " VALUES (?, ?, ?, ?)",
                    (digest, station_id, canonical_payload, now),
                )
                self._conn.execute(
                    "INSERT INTO receipts (station_id, nonce, digest, received_at)"
                    " VALUES (?, ?, ?, ?)",
                    (station_id, nonce, digest, now),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def lookup_receipt(self, station_id: str,
                       nonce: str) -> tuple[str, Receipt | None]:
        """按 (站点, nonce) 查询接纳回执；纯只读，不登记也不改写任何记录。

        返回 (RECEIPT_OK, Receipt)      —— 回执存在，可核对摘要；
             (RECEIPT_UNAVAILABLE, None) —— nonce 已登记但无回执（旧数据卷）；
             (RECEIPT_MISSING, None)     —— nonce 从未登记。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT digest, received_at FROM receipts"
                " WHERE station_id = ? AND nonce = ?",
                (station_id, nonce),
            ).fetchone()
            if row is not None:
                return RECEIPT_OK, Receipt(digest=row[0], received_at=row[1])
            seen = self._conn.execute(
                "SELECT 1 FROM nonces WHERE station_id = ? AND nonce = ?",
                (station_id, nonce),
            ).fetchone()
            if seen is not None:
                return RECEIPT_UNAVAILABLE, None
            return RECEIPT_MISSING, None

    def lookup_event_payload(self, digest: str) -> str | None:
        """按事件摘要取首次接纳时保存的规范化载荷文本；纯只读。

        供恢复端点在摘要文本不直接相等时，按数值语义复核既有回执
        （旧版本数据卷中的回执摘要未做数字归一化）。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM events WHERE digest = ?", (digest,)
            ).fetchone()
            return row[0] if row is not None else None

    def nonce_seen(self, station_id: str, nonce: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM nonces WHERE station_id = ? AND nonce = ?",
                (station_id, nonce),
            ).fetchone()
            return row is not None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
