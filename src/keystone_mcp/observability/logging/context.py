"""Request-scoped logging context."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Final

_REQUEST_ID: ContextVar[str | None] = ContextVar("keystone_mcp_request_id", default=None)

DEFAULT_REQUEST_ID_HEADER: Final = "X-Request-ID"


def get_request_id() -> str | None:
    return _REQUEST_ID.get()


def set_request_id(request_id: str | None) -> Token[str | None]:
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    _REQUEST_ID.reset(token)
