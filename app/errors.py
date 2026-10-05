"""统一的 API 错误类型：每种失败都有可区分的 (HTTP 状态, 错误码) 组合。"""
from __future__ import annotations


class ApiError(Exception):
    """可直接转换为 HTTP JSON 响应的业务错误。"""

    def __init__(self, status: int, code: str, message: str, detail: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict:
        err = {"code": self.code, "message": self.message}
        if self.detail:
            err["detail"] = self.detail
        return {"error": err}
