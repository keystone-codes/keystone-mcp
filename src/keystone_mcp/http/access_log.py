"""HTTP access logging middleware (replaces uvicorn access log)."""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import TYPE_CHECKING

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from keystone_mcp.observability.logging.context import reset_request_id, set_request_id

if TYPE_CHECKING:
    from keystone_mcp.config import Settings

_ACCESS_LOGGER = logging.getLogger("keystone_mcp.access")


def _client_ip(scope: Scope) -> str | None:
    client = scope.get("client")
    if not client:
        return None
    return str(client[0])


def _path_without_query(scope: Scope) -> str:
    path = scope.get("path", "")
    return path.split("?", 1)[0]


def _header_value(scope: Scope, name: str) -> str | None:
    name_lower = name.lower()
    for key, value in scope.get("headers", ()):
        if key.decode("latin-1").lower() == name_lower:
            return value.decode("latin-1")
    return None


_JWT_LIKE_REQUEST_ID = re.compile(r"^eyJ[A-Za-z0-9_-]+\.")


def resolve_request_id(scope: Scope, *, header_name: str) -> str:
    incoming = _header_value(scope, header_name)
    if incoming and incoming.strip():
        candidate = incoming.strip()
        if len(candidate) > 128 or _JWT_LIKE_REQUEST_ID.match(candidate):
            return str(uuid.uuid4())
        return candidate
    return str(uuid.uuid4())


class AccessLogMiddleware:
    """Log one line per HTTP request without query strings or credentials."""

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self.app = app
        self._settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500
        request_id = resolve_request_id(
            scope,
            header_name=self._settings.log_request_id_header,
        )
        token = set_request_id(request_id)
        response_header = self._settings.log_request_id_header.encode("latin-1")
        response_value = request_id.encode("latin-1")
        echo_id = self._settings.log_request_id_response

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                if echo_id:
                    headers = list(message.get("headers", []))
                    if not any(h[0].lower() == response_header.lower() for h in headers):
                        headers.append((response_header, response_value))
                    message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if self._settings.log_access_enabled:
                duration_ms = round((time.perf_counter() - started) * 1000, 2)
                _ACCESS_LOGGER.info(
                    "http access",
                    extra={
                        "stream": "access",
                        "method": scope.get("method", ""),
                        "path": _path_without_query(scope),
                        "status": status_code,
                        "duration_ms": duration_ms,
                        "client_ip": _client_ip(scope),
                        "request_id": request_id,
                    },
                )
            reset_request_id(token)
