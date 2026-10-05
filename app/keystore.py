"""已登记设备密钥的加载与有效期校验。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone


def _parse_instant(value: str) -> float:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass(frozen=True)
class Key:
    key_id: str
    station_id: str
    secret: str
    not_before: float
    not_after: float

    def is_active(self, now: float) -> bool:
        return self.not_before <= now <= self.not_after


class KeyStore:
    def __init__(self, keys: list[Key]):
        self._keys = {k.key_id: k for k in keys}
        if len(self._keys) != len(keys):
            raise ValueError("duplicate key_id in key file")

    @classmethod
    def load(cls, path: str) -> "KeyStore":
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        keys = []
        for item in doc.get("keys", []):
            keys.append(Key(
                key_id=str(item["key_id"]),
                station_id=str(item["station_id"]),
                secret=str(item["secret"]),
                not_before=_parse_instant(item["not_before"]),
                not_after=_parse_instant(item["not_after"]),
            ))
        if not keys:
            raise ValueError(f"no keys defined in {path}")
        return cls(keys)

    def get(self, key_id: str) -> Key | None:
        return self._keys.get(key_id)

    def __len__(self) -> int:
        return len(self._keys)
