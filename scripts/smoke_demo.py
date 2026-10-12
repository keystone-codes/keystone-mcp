#!/usr/bin/env python3
"""End-to-end smoke test for the demo compose stack (docker-compose.demo.yml).

Drives the release readiness scenario against a *running* server: DEV-token
OAuth sign-in (DCR -> authorize -> login -> token, the same sequence a real
MCP client runs), a call to every ``hello_*`` tool from the sample upstream, a
check that ``hello_whoami`` shows the administrator's identity as verified by
hello-upstream (the demo's ``X-Keystone-Identity`` signing secret, see
``docker-compose.demo.yml`` and ``examples/demo/upstreams.yaml``), adding a
second user with a role that cannot see ``users_*``, and a check that the new
role really is denied those tools.

Usage::

    uv run python scripts/smoke_demo.py --dev-token <token> --admin-email <email>

Every argument has a ``SMOKE_*`` environment variable fallback (never
``KEYSTONE_MCP_*``, so this script's own configuration can never collide with
the env/docs sync check that compares ``KEYSTONE_MCP_*`` names across
``config.py``, ``.env.example`` and ``docs/environment.md``).

Each step prints exactly one ``[PASS] <step>`` or ``[FAIL] <step>: expected
<X>, got <Y>`` line and the script stops at the first failure, exiting 1.
Tokens are never printed -- only their length, when that is useful at all.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

#: Redirect URI for the throwaway OAuth client this script registers. Nothing
#: ever listens on it -- the script reads the authorization code straight out
#: of the redirect response instead of following it.
REDIRECT_URI = "http://127.0.0.1:9/callback"

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_MEMBER_EMAIL = "member@example.com"
DEFAULT_MEMBER_ROLE = "member"


class SmokeError(Exception):
    """A step's expectation was not met; carries a human-readable reason."""


def build_minimal_args(input_schema: dict[str, Any] | None) -> dict[str, Any]:
    """Build the smallest argument dict that satisfies a tool's ``input_schema``.

    Only required properties are filled in, with one fixed placeholder value
    per JSON Schema type, so this script never needs to know a tool's actual
    name or semantics -- it just needs the call to go through. A required
    property with an ``enum`` gets its first listed value instead of the
    plain type placeholder (the demo's own ``hello_search`` has exactly this
    shape: a required ``filter: {"type": "string", "enum": ["all", "mine"]}``,
    which the fixed string placeholder would fail schema validation on).
    """
    if not input_schema:
        return {}
    properties: dict[str, Any] = input_schema.get("properties") or {}
    required: list[str] = input_schema.get("required") or []

    placeholders: dict[str, Any] = {
        "string": "smoke",
        "integer": 1,
        "number": 1.0,
        "boolean": True,
        "array": [],
        "object": {},
    }

    args: dict[str, Any] = {}
    for name in required:
        prop = properties.get(name) or {}
        enum_values = prop.get("enum")
        if enum_values:
            args[name] = enum_values[0]
            continue
        prop_type = prop.get("type")
        args[name] = placeholders.get(prop_type, "smoke")
    return args


def make_pkce() -> tuple[str, str]:
    """A fresh PKCE S256 (code_verifier, code_challenge) pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


async def discover_oauth_metadata(client: httpx.AsyncClient, base_url: str) -> dict[str, Any]:
    """Fetch and validate the protected-resource and authorization-server metadata.

    Returns a flat dict with ``resource``, ``authorization_endpoint``,
    ``token_endpoint`` and ``registration_endpoint``; raises ``SmokeError`` if
    either document is missing, is not 200, or lacks a field a client needs.
    """
    prm_resp = await client.get(f"{base_url}/.well-known/oauth-protected-resource")
    if prm_resp.status_code != 200:
        raise SmokeError(
            f"GET /.well-known/oauth-protected-resource: expected 200, got {prm_resp.status_code}"
        )
    prm = prm_resp.json()
    if not prm.get("resource"):
        raise SmokeError("protected-resource metadata has no 'resource' field")

    asm_resp = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
    if asm_resp.status_code != 200:
        raise SmokeError(
            f"GET /.well-known/oauth-authorization-server: expected 200, got {asm_resp.status_code}"
        )
    asm = asm_resp.json()
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        if not asm.get(key):
            raise SmokeError(f"authorization-server metadata is missing '{key}'")
    if "S256" not in asm.get("code_challenge_methods_supported", []):
        raise SmokeError("authorization-server metadata does not advertise PKCE S256")

    return {
        "resource": prm["resource"],
        "authorization_endpoint": asm["authorization_endpoint"],
        "token_endpoint": asm["token_endpoint"],
        "registration_endpoint": asm["registration_endpoint"],
    }


async def register_client(client: httpx.AsyncClient, registration_endpoint: str) -> str:
    """Dynamic client registration (RFC 7591); returns the new ``client_id``."""
    resp = await client.post(
        registration_endpoint,
        json={
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
        },
    )
    if resp.status_code not in (200, 201):
        raise SmokeError(
            f"client registration: expected 201/200, got {resp.status_code} {resp.text}"
        )
    client_id = resp.json().get("client_id")
    if not client_id:
        raise SmokeError("client registration response has no 'client_id'")
    return client_id


async def start_authorization(
    client: httpx.AsyncClient,
    authorization_endpoint: str,
    client_id: str,
    resource: str,
) -> tuple[str, str, str]:
    """``GET`` the authorization endpoint; returns (txn, code_verifier, state)."""
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(16)
    resp = await client.get(
        authorization_endpoint,
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": resource,
        },
        follow_redirects=False,
    )
    if resp.status_code not in (302, 307):
        raise SmokeError(f"authorize: expected 302/307, got {resp.status_code} {resp.text}")
    location = resp.headers.get("location", "")
    txn = parse_qs(urlparse(location).query).get("txn", [None])[0]
    if not txn:
        raise SmokeError(f"authorize redirect has no 'txn': {location}")
    return txn, verifier, state


async def complete_login(
    client: httpx.AsyncClient,
    base_url: str,
    txn: str,
    dev_token: str,
    email: str,
    expected_state: str,
) -> str:
    """``POST /login`` with the DEV token; returns the authorization code."""
    resp = await client.post(
        f"{base_url}/login",
        data={"txn": txn, "api_token": dev_token, "email": email},
        follow_redirects=False,
    )
    if resp.status_code != 302:
        raise SmokeError(f"/login: expected 302, got {resp.status_code} {resp.text}")
    location = resp.headers.get("location", "")
    qs = parse_qs(urlparse(location).query)
    code = qs.get("code", [None])[0]
    state = qs.get("state", [None])[0]
    if not code:
        raise SmokeError(f"/login redirect has no 'code': {location}")
    if state != expected_state:
        raise SmokeError(
            f"/login redirect 'state' mismatch: sent {expected_state!r}, got {state!r}"
        )
    return code


async def exchange_token(
    client: httpx.AsyncClient,
    token_endpoint: str,
    code: str,
    client_id: str,
    verifier: str,
    resource: str,
) -> str:
    """``POST`` the token endpoint; returns the bearer access token."""
    resp = await client.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource,
        },
    )
    if resp.status_code != 200:
        raise SmokeError(f"token exchange: expected 200, got {resp.status_code} {resp.text}")
    access_token = resp.json().get("access_token")
    if not access_token:
        raise SmokeError("token response has no 'access_token'")
    return access_token


async def oauth_login(
    client: httpx.AsyncClient,
    base_url: str,
    dev_token: str,
    email: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Run the full DCR -> authorize -> login -> token flow; returns an access token."""
    meta = metadata if metadata is not None else await discover_oauth_metadata(client, base_url)
    client_id = await register_client(client, meta["registration_endpoint"])
    txn, verifier, state = await start_authorization(
        client, meta["authorization_endpoint"], client_id, meta["resource"]
    )
    code = await complete_login(client, base_url, txn, dev_token, email, state)
    return await exchange_token(
        client, meta["token_endpoint"], code, client_id, verifier, meta["resource"]
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SMOKE_BASE_URL", DEFAULT_BASE_URL),
        help=f"Base URL of the running server (default: {DEFAULT_BASE_URL}, env SMOKE_BASE_URL).",
    )
    parser.add_argument(
        "--dev-token",
        default=os.environ.get("SMOKE_DEV_TOKEN"),
        help="DEV token configured on the server (env SMOKE_DEV_TOKEN). Required.",
    )
    parser.add_argument(
        "--admin-email",
        default=os.environ.get("SMOKE_ADMIN_EMAIL"),
        help="Email of the seeded administrator (env SMOKE_ADMIN_EMAIL). Required.",
    )
    parser.add_argument(
        "--member-email",
        default=os.environ.get("SMOKE_MEMBER_EMAIL", DEFAULT_MEMBER_EMAIL),
        help=f"Email for the new member user (default: {DEFAULT_MEMBER_EMAIL}, env SMOKE_MEMBER_EMAIL).",
    )
    parser.add_argument(
        "--member-role",
        default=os.environ.get("SMOKE_MEMBER_ROLE", DEFAULT_MEMBER_ROLE),
        help=f"Role granted to the new member (default: {DEFAULT_MEMBER_ROLE}, env SMOKE_MEMBER_ROLE).",
    )
    args = parser.parse_args(argv)
    if not args.dev_token:
        parser.error("--dev-token is required (or set SMOKE_DEV_TOKEN)")
    if not args.admin_email:
        parser.error("--admin-email is required (or set SMOKE_ADMIN_EMAIL)")
    return args


class _StepLog:
    """Prints exactly one PASS/FAIL line per step and counts passes."""

    def __init__(self) -> None:
        self.passed = 0

    def ok(self, step: str) -> None:
        self.passed += 1
        print(f"[PASS] {step}")

    def fail(self, step: str, expected: str, got: str) -> None:
        print(f"[FAIL] {step}: expected {expected}, got {got}")


async def run(args: argparse.Namespace) -> int:
    base_url = args.base_url.rstrip("/")
    transport_url = f"{base_url}/"
    log = _StepLog()

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        # 1. GET /healthz
        step = "GET /healthz"
        try:
            resp = await client.get(f"{base_url}/healthz")
            body = resp.json() if resp.content else {}
            if resp.status_code != 200 or body != {"status": "ok"}:
                log.fail(step, "200 {'status': 'ok'}", f"{resp.status_code} {body}")
                return 1
            log.ok(step)
        except Exception as exc:  # noqa: BLE001 - report and stop, any cause
            log.fail(step, "200 {'status': 'ok'}", repr(exc))
            return 1

        # 2. GET /readyz
        step = "GET /readyz"
        try:
            resp = await client.get(f"{base_url}/readyz")
            if resp.status_code != 200:
                log.fail(step, "200", f"{resp.status_code} {resp.text}")
                return 1
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(step, "200", repr(exc))
            return 1

        # 3. OAuth discovery metadata
        step = "OAuth discovery metadata"
        try:
            metadata = await discover_oauth_metadata(client, base_url)
            log.ok(step)
        except (SmokeError, Exception) as exc:  # noqa: BLE001
            log.fail(step, "resource + AS metadata with S256 PKCE", repr(exc))
            return 1

        resource = metadata["resource"]

        # 4. Dynamic client registration (admin)
        step = "Dynamic client registration (admin)"
        try:
            admin_client_id = await register_client(client, metadata["registration_endpoint"])
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(step, "201/200 with client_id", repr(exc))
            return 1

        # 5. Authorization redirect to /login (admin)
        step = "Authorization redirect to /login (admin)"
        try:
            admin_txn, admin_verifier, admin_state = await start_authorization(
                client, metadata["authorization_endpoint"], admin_client_id, resource
            )
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(step, "302/307 redirect with txn", repr(exc))
            return 1

        # 6. Login with the DEV token (admin)
        step = "Login with DEV token (admin)"
        try:
            admin_code = await complete_login(
                client, base_url, admin_txn, args.dev_token, args.admin_email, admin_state
            )
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(step, "302 redirect with code and matching state", repr(exc))
            return 1

        # 7. Token exchange (admin)
        step = "Token exchange (admin)"
        try:
            admin_token = await exchange_token(
                client,
                metadata["token_endpoint"],
                admin_code,
                admin_client_id,
                admin_verifier,
                resource,
            )
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(step, "200 with access_token", repr(exc))
            return 1

        # 8-11 run inside one administrator MCP session.
        try:
            async with Client(StreamableHttpTransport(transport_url, auth=admin_token)) as admin:
                # 8. Administrator sees hello_* and users_*
                step = "Administrator tool list has hello_* and users_*"
                try:
                    tools = await admin.list_tools()
                    names = {t.name for t in tools}
                    has_hello = any(n.startswith("hello_") for n in names)
                    if not has_hello or "users_add" not in names or "users_list" not in names:
                        raise SmokeError(f"tool list was: {sorted(names)}")
                    hello_tools = [t for t in tools if t.name.startswith("hello_")]
                    log.ok(step)
                except Exception as exc:  # noqa: BLE001
                    log.fail(step, "at least one hello_* plus users_add and users_list", repr(exc))
                    return 1

                # 9. Call every hello_* tool
                step = "Call every hello_* tool"
                try:
                    for tool in hello_tools:
                        tool_args = build_minimal_args(tool.input_schema)
                        result = await admin.call_tool(tool.name, tool_args)
                        if result.is_error:
                            raise SmokeError(f"{tool.name} returned an error: {result.data}")
                        if not result.content:
                            raise SmokeError(f"{tool.name} returned empty content")
                    log.ok(step)
                except Exception as exc:  # noqa: BLE001
                    log.fail(step, "every hello_* call succeeds with non-empty content", repr(exc))
                    return 1

                # 10. hello_whoami shows the identity Keystone verified
                step = "hello_whoami shows the verified administrator identity"
                try:
                    result = await admin.call_tool("hello_whoami", {})
                    if result.is_error:
                        raise SmokeError(f"hello_whoami returned an error: {result.content}")
                    text = result.content[0].text if result.content else ""
                    payload = json.loads(text)
                    roles = payload.get("roles") or []
                    sub = (payload.get("sub") or "").lower()
                    if (
                        not payload.get("verified")
                        or "administrator" not in roles
                        or sub != args.admin_email.lower()
                    ):
                        raise SmokeError(f"unexpected hello_whoami payload: {payload}")
                    log.ok(step)
                except Exception as exc:  # noqa: BLE001
                    log.fail(
                        step,
                        "verified, roles include 'administrator', sub == admin email",
                        repr(exc),
                    )
                    return 1

                # 11. users_add for the member
                step = "users_add (member)"
                try:
                    added = await admin.call_tool(
                        "users_add",
                        {
                            "email": args.member_email,
                            "full_name": "Smoke Member",
                            "roles": [args.member_role],
                        },
                    )
                    state = added.data.get("state")
                    code = added.data.get("code")
                    if state == "done" or (state == "error" and code == "conflict"):
                        log.ok(step)
                    else:
                        raise SmokeError(f"unexpected result: {added.data}")
                except Exception as exc:  # noqa: BLE001
                    log.fail(step, "done, or error code 'conflict' on a rerun", repr(exc))
                    return 1
        except SmokeError as exc:
            log.fail(step, "-", repr(exc))
            return 1

        # 12. Repeat steps 4-7 for the member
        step = "Repeat DEV-token login (member)"
        try:
            member_token = await oauth_login(
                client, base_url, args.dev_token, args.member_email, metadata=metadata
            )
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(step, "DCR, authorize, login and token exchange all succeed", repr(exc))
            return 1

        # 13. Member session: hello_* only, no users_*
        step = "Member sees only hello_*, users_* is denied"
        try:
            async with Client(StreamableHttpTransport(transport_url, auth=member_token)) as member:
                tools = await member.list_tools()
                names = {t.name for t in tools}
                has_hello = any(n.startswith("hello_") for n in names)
                has_users = any(n.startswith("users_") for n in names)
                if not has_hello or has_users:
                    raise SmokeError(f"tool list was: {sorted(names)}")

                first_hello = next(t for t in tools if t.name.startswith("hello_"))
                result = await member.call_tool(
                    first_hello.name, build_minimal_args(first_hello.input_schema)
                )
                if result.is_error:
                    raise SmokeError(f"{first_hello.name} returned an error: {result.data}")

                denied = False
                try:
                    await member.call_tool("users_list", {})
                except Exception:  # noqa: BLE001 - any exception is the expected denial
                    denied = True
                if not denied:
                    raise SmokeError("users_list was not denied to the member role")
            log.ok(step)
        except Exception as exc:  # noqa: BLE001
            log.fail(
                step,
                "hello_* visible and callable, users_* absent, users_list call denied",
                repr(exc),
            )
            return 1

    print(f"{log.passed}/13 steps passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
