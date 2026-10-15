#!/usr/bin/env python3
"""End-to-end check with the official MCP Python SDK OAuth client (no Keystone test helpers).

Runs against a live demo stack: OAuthClientProvider handles discovery, DCR, PKCE and
refresh; this script only simulates the browser login form via httpx + HTML parsing.

Usage::

    uv run python scripts/client_e2e.py \\
        --base-url http://localhost:8080 \\
        --dev-token ci-smoke-token \\
        --email member@example.com \\
        --protocol modern
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import importlib.util
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import httpx2
import mcp.types as types
from mcp.client.auth import OAuthClientProvider
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.client.subscriptions import listen as listen_subscriptions
from mcp.shared._httpx_utils import MCP_DEFAULT_SSE_READ_TIMEOUT, MCP_DEFAULT_TIMEOUT
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

_helpers_spec = importlib.util.spec_from_file_location(
    "client_e2e_helpers",
    Path(__file__).resolve().parent / "client_e2e_helpers.py",
)
assert _helpers_spec is not None and _helpers_spec.loader is not None
_helpers = importlib.util.module_from_spec(_helpers_spec)
_helpers_spec.loader.exec_module(_helpers)
parse_api_key_login_form = _helpers.parse_api_key_login_form
parse_oauth_callback_location = _helpers.parse_oauth_callback_location
summarize_clients_md_row = _helpers.summarize_clients_md_row
tool_result_text = _helpers.tool_result_text

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_MEMBER_EMAIL = "member@example.com"
DEFAULT_ADMIN_EMAIL = "admin@example.com"
REDIRECT_PORT = 18765
MCP_SDK_VERSION = importlib.metadata.version("mcp")
MODERN_VERSION = "2026-07-28"


@dataclass
class MemoryTokenStorage:
    """In-memory TokenStorage for a single OAuth client registration."""

    tokens: OAuthToken | None = None
    client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


@dataclass
class BrowserLoginState:
    code: str | None = None
    state: str | None = None


@dataclass
class StepLog:
    passed: int = 0
    skipped: list[str] = field(default_factory=list)

    def ok(self, step: str) -> None:
        self.passed += 1
        print(f"ok {step}")

    def skip(self, step: str, reason: str) -> None:
        self.skipped.append(step)
        print(f"skip {step}: {reason}")

    def fail(self, step: str, reason: str) -> None:
        print(f"FAIL {step}: {reason}")


@dataclass
class OAuthFlowTrace:
    redirect_opens: int = 0
    refresh_token_posts: int = 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--dev-token", required=True)
    parser.add_argument("--email", default=DEFAULT_MEMBER_EMAIL)
    parser.add_argument("--admin-email", default=DEFAULT_ADMIN_EMAIL)
    parser.add_argument("--protocol", choices=("modern", "legacy"), required=True)
    return parser.parse_args(argv)


async def _browser_login(
    *,
    authorize_url: str,
    base_url: str,
    dev_token: str,
    email: str,
    redirect_uri: str,
    login_state: BrowserLoginState,
) -> None:
    async with httpx.AsyncClient(base_url=base_url, follow_redirects=False, timeout=30.0) as client:
        resp = await client.get(authorize_url, follow_redirects=True)
        if resp.status_code != 200:
            raise RuntimeError(
                f"authorize flow ended with HTTP {resp.status_code}, not a login page"
            )
        action, fields = parse_api_key_login_form(resp.text, page_url=str(resp.url))
        fields["email"] = email
        fields["api_token"] = dev_token
        post = await client.post(action, data=fields, follow_redirects=False)
        if post.status_code not in (302, 307):
            raise RuntimeError(f"login POST returned {post.status_code}: {post.text[:200]}")
        location = post.headers.get("location")
        if not location:
            raise RuntimeError("login POST missing Location header")
        code, state = parse_oauth_callback_location(location, redirect_uri=redirect_uri)
        login_state.code = code
        login_state.state = state


def _token_request_hook(trace: OAuthFlowTrace):
    async def _hook(request: httpx2.Request) -> None:
        if request.method.upper() != "POST":
            return
        path = urlparse(str(request.url)).path.rstrip("/")
        if not path.endswith("/token"):
            return
        body = request.content.decode("utf-8", errors="replace")
        grant = parse_qs(body).get("grant_type", [None])[0]
        if grant == "refresh_token":
            trace.refresh_token_posts += 1
            print("ok token refresh request (grant_type=refresh_token)")

    return _hook


def _build_oauth_provider(
    *,
    base_url: str,
    redirect_uri: str,
    storage: MemoryTokenStorage,
    login_state: BrowserLoginState,
    trace: OAuthFlowTrace,
    dev_token: str,
    email: str,
) -> OAuthClientProvider:
    async def redirect_handler(url: str) -> None:
        trace.redirect_opens += 1
        await _browser_login(
            authorize_url=url,
            base_url=base_url,
            dev_token=dev_token,
            email=email,
            redirect_uri=redirect_uri,
            login_state=login_state,
        )

    async def callback_handler() -> AuthorizationCodeResult:
        if login_state.code is None or login_state.state is None:
            raise RuntimeError("callback_handler called before browser login captured code/state")
        return AuthorizationCodeResult(code=login_state.code, state=login_state.state)

    return OAuthClientProvider(
        server_url=base_url.rstrip("/"),
        client_metadata=OAuthClientMetadata(
            client_name="keystone-client-e2e",
            redirect_uris=[redirect_uri],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )


async def _open_mcp_session(
    *,
    base_url: str,
    protocol: str,
    dev_token: str,
    email: str,
    elicitation_handler,
    message_handler,
    trace: OAuthFlowTrace,
) -> tuple[ClientSession, Any, MemoryTokenStorage, OAuthClientProvider, str]:
    redirect_uri = f"http://127.0.0.1:{REDIRECT_PORT}/callback"
    storage = MemoryTokenStorage()
    login_state = BrowserLoginState()
    auth = _build_oauth_provider(
        base_url=base_url,
        redirect_uri=redirect_uri,
        storage=storage,
        login_state=login_state,
        trace=trace,
        dev_token=dev_token,
        email=email,
    )

    timeout = httpx2.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT)
    http_client = httpx2.AsyncClient(
        timeout=timeout,
        auth=auth,
        event_hooks={"request": [_token_request_hook(trace)]},
    )
    transport_url = f"{base_url.rstrip('/')}/"
    stack = asyncio.AsyncExitStack()
    await stack.enter_async_context(http_client)
    read_stream, write_stream, _ = await stack.enter_async_context(
        streamable_http_client(transport_url, http_client=http_client)
    )
    session = ClientSession(
        read_stream,
        write_stream,
        read_timeout_seconds=timedelta(seconds=120),
        elicitation_callback=elicitation_handler,
        message_handler=message_handler,
    )
    await stack.enter_async_context(session)
    if protocol == "modern":
        await session.discover()
    else:
        await session.initialize()
    return session, stack, storage, auth, redirect_uri


async def _admin_policy_allow_member_pattern(
    *,
    base_url: str,
    dev_token: str,
    admin_email: str,
    pattern: str,
    trace: OAuthFlowTrace,
) -> None:
    async def _noop_elicitation(_ctx, _params):
        return types.ErrorData(code=types.INVALID_REQUEST, message="no")

    async def _noop_message(_msg) -> None:
        pass

    session, stack, _storage, _auth, _redirect = await _open_mcp_session(
        base_url=base_url,
        protocol="modern",
        dev_token=dev_token,
        email=admin_email,
        elicitation_handler=_noop_elicitation,
        message_handler=_noop_message,
        trace=trace,
    )
    try:
        policy = await session.call_tool("policy_read", {})
        if policy.is_error:
            raise RuntimeError(tool_result_text(policy))
        data = _tool_json_payload(policy)
        expected_hash = data.get("content_hash")
        if not expected_hash:
            raise RuntimeError(f"policy_read missing content_hash: {data!r}")
        result = await session.call_tool(
            "policy_allow_add",
            {"role": "member", "patterns": [pattern], "expected_hash": expected_hash},
        )
        if result.is_error:
            raise RuntimeError(tool_result_text(result))
    finally:
        await stack.aclose()


def _tool_json_payload(result: types.CallToolResult) -> dict[str, Any]:
    if result.structured_content is not None and isinstance(result.structured_content, dict):
        return result.structured_content
    text = tool_result_text(result)
    if text.startswith("{"):
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    raise RuntimeError(f"tool result is not JSON object: {text[:200]!r}")


async def run(args: argparse.Namespace) -> int:
    base_url = args.base_url.rstrip("/")
    log = StepLog()
    trace = OAuthFlowTrace()
    outcomes = {
        "sign_in": "no",
        "refresh": "no",
        "tools": "no",
        "list_changed": "no",
        "progress": "no",
        "cancel": "no",
        "elicitation": "no",
    }

    list_changed_event = asyncio.Event()
    notifications: list[Any] = []

    async def on_message(message) -> None:
        method = getattr(message, "method", None)
        if method is None and isinstance(message, types.ServerNotification):
            method = getattr(message.root, "method", None)
        if method == "notifications/tools/list_changed":
            notifications.append(message)
            list_changed_event.set()

    async def on_elicitation(_ctx, params: types.ElicitRequestParams):
        return types.ElicitResult(action="accept", content={"name": "ci"})

    try:
        session, stack, storage, auth, _redirect_uri = await _open_mcp_session(
            base_url=base_url,
            protocol=args.protocol,
            dev_token=args.dev_token,
            email=args.email,
            elicitation_handler=on_elicitation,
            message_handler=on_message,
            trace=trace,
        )
    except Exception as exc:  # noqa: BLE001
        log.fail("sign-in", repr(exc))
        return 1

    try:
        step = "initialize"
        version = session._negotiated_version  # noqa: SLF001
        if args.protocol == "modern":
            if version not in MODERN_PROTOCOL_VERSIONS:
                log.fail(step, f"modern protocol, got {version!r}")
                return 1
        elif version not in HANDSHAKE_PROTOCOL_VERSIONS:
            log.fail(step, f"legacy handshake, got {version!r}")
            return 1
        log.ok(step)
        outcomes["sign_in"] = "yes"

        step = "tools/list"
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        if "hello_greet" not in names:
            log.fail(step, f"hello_greet missing; have {sorted(names)[:10]}")
            return 1
        log.ok(step)
        outcomes["tools"] = "yes"

        step = "tools/call hello_greet"
        greet = await session.call_tool("hello_greet", {"name": "ci"})
        if greet.is_error:
            log.fail(step, tool_result_text(greet))
            return 1
        text = tool_result_text(greet)
        if "ci" not in text.lower():
            log.fail(step, f"response missing greeting: {text!r}")
            return 1
        log.ok(step)

        step = "progress hello_slow_count"
        progress_hits = 0

        async def on_progress(_progress: float, _total: float | None, _message: str | None) -> None:
            nonlocal progress_hits
            progress_hits += 1

        slow = await session.call_tool(
            "hello_slow_count",
            {"n": 3},
            progress_callback=on_progress,
        )
        if slow.is_error:
            log.fail(step, tool_result_text(slow))
            return 1
        if progress_hits < 2:
            log.fail(step, f"expected >=2 progress notifications, got {progress_hits}")
            return 1
        log.ok(step)
        outcomes["progress"] = "yes"

        step = "cancel hello_slow_count"
        t0 = time.monotonic()
        slow_task = asyncio.create_task(session.call_tool("hello_slow_count", {"n": 30}))
        await asyncio.sleep(1.0)
        slow_task.cancel()
        try:
            await slow_task
            log.fail(step, "call completed without cancellation")
            return 1
        except asyncio.CancelledError:
            elapsed = time.monotonic() - t0
            if elapsed >= 5.0:
                log.fail(step, f"cancel took {elapsed:.1f}s (limit 5s)")
                return 1
            log.ok(step)
            outcomes["cancel"] = "yes"

        step = "elicitation hello_ask_name"
        try:
            ask = await session.call_tool("hello_ask_name", {})
        except Exception as exc:  # noqa: BLE001
            log.skip(step, repr(exc))
        else:
            if ask.is_error:
                log.skip(step, tool_result_text(ask))
            else:
                answer = tool_result_text(ask)
                if "elicitation not available" in answer or "no-elicitation" in answer:
                    log.skip(step, answer)
                elif "ci" in answer:
                    log.ok(step)
                    outcomes["elicitation"] = "yes"
                else:
                    log.fail(step, f"unexpected answer: {answer!r}")
                    return 1

        step = "list_changed"
        list_changed_event.clear()
        listener_stack = asyncio.AsyncExitStack()
        if args.protocol == "modern":
            sub = await listener_stack.enter_async_context(
                listen_subscriptions(session, tools_list_changed=True)
            )

            async def _wait_modern() -> None:
                await asyncio.wait_for(sub.__anext__(), timeout=10.0)

            wait_task = asyncio.create_task(_wait_modern())
        else:
            wait_task = asyncio.create_task(
                asyncio.wait_for(list_changed_event.wait(), timeout=10.0)
            )

        await _admin_policy_allow_member_pattern(
            base_url=base_url,
            dev_token=args.dev_token,
            admin_email=args.admin_email,
            pattern="notes_list",
            trace=OAuthFlowTrace(),
        )
        try:
            await wait_task
            log.ok(step)
            outcomes["list_changed"] = "yes"
        except TimeoutError:
            log.fail(step, "no notifications/tools/list_changed within 10s")
            return 1
        finally:
            await listener_stack.aclose()

        step = "token refresh"
        tokens = storage.tokens
        if tokens is None:
            log.fail(step, "no tokens in storage")
            return 1
        expired = tokens.model_copy(update={"expires_in": -1})
        await storage.set_tokens(expired)
        auth.context.current_tokens = expired
        auth.context.update_token_expiry(expired)
        before_refresh_posts = trace.refresh_token_posts
        ping = await session.call_tool("hello_greet", {"name": "refresh"})
        if ping.is_error:
            log.fail(step, tool_result_text(ping))
            return 1
        if trace.refresh_token_posts <= before_refresh_posts:
            log.fail(step, "no refresh_token grant observed on /token")
            return 1
        if trace.redirect_opens != 1:
            log.fail(step, f"redirect_handler called {trace.redirect_opens} times (want 1)")
            return 1
        log.ok(step)
        outcomes["refresh"] = "yes"

    finally:
        await stack.aclose()

    protocol_label = MODERN_VERSION if args.protocol == "modern" else "handshake"
    elicitation_cell = (
        outcomes["elicitation"]
        if outcomes["elicitation"] == "yes"
        else ("n/a" if log.skipped else "no")
    )
    print(
        summarize_clients_md_row(
            sdk_version=MCP_SDK_VERSION,
            protocol_label=protocol_label,
            sign_in=outcomes["sign_in"],
            refresh=outcomes["refresh"],
            tools=outcomes["tools"],
            list_changed=outcomes["list_changed"],
            progress=outcomes["progress"],
            cancel=outcomes["cancel"],
            elicitation=elicitation_cell,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
