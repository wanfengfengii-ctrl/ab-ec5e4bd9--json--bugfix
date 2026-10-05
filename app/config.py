"""环境变量配置。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_KEYS = Path(__file__).resolve().parent.parent / "keys" / "keys.json"


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 8000
    keys_file: str = str(_DEFAULT_KEYS)
    data_dir: str = "./data"
    skew_seconds: int = 300            # 允许的发送时刻偏差（五分钟）
    max_body_bytes: int = 5 * 1024 * 1024
    max_decompressed_bytes: int = 10 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "8000")),
            keys_file=os.environ.get("KEYS_FILE", str(_DEFAULT_KEYS)),
            data_dir=os.environ.get("DATA_DIR", "./data"),
            skew_seconds=int(os.environ.get("SKEW_SECONDS", "300")),
            max_body_bytes=int(os.environ.get("MAX_BODY_BYTES", str(5 * 1024 * 1024))),
            max_decompressed_bytes=int(os.environ.get("MAX_DECOMPRESSED_BYTES", str(10 * 1024 * 1024))),
        )
