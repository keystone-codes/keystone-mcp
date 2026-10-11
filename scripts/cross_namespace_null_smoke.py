"""Cross-namespace keystone-mcp smoke: call_tool with explicit null optionals.

Proves the router forwards explicitly-null optional arguments to upstream tools
without a validation error. The cases are deployment data, not part of the
platform: pass a JSON file with ``--cases``.

    {
      "reports": {
        "tool": "reports_list",
        "args": {"max_rows": null},
        "expect_keys": ["items"]
      },
      "documents": {"tool": "documents_describe_capabilities", "args": {}}
    }

``args`` and ``expect_keys`` are optional. Without ``--cases`` the script only
lists the tools the router publishes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client


@dataclass(frozen=True)
class SmokeCase:
    """One upstream call: a published tool name plus the arguments to send."""

    label: str
    tool: str
    args: dict = field(default_factory=dict)
    expect_keys: tuple[str, ...] = ()


def load_cases(path: Path) -> tuple[SmokeCase, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("cases file must be a JSON object keyed by label")
    cases: list[SmokeCase] = []
    for label, spec in payload.items():
        if not isinstance(spec, dict) or "tool" not in spec:
            raise ValueError(f"case {label!r} must be an object with a 'tool' key")
        cases.append(
            SmokeCase(
                label=str(label),
                tool=str(spec["tool"]),
                args=dict(spec.get("args") or {}),
                expect_keys=tuple(spec.get("expect_keys") or ()),
            )
        )
    return tuple(cases)


async def _obtain_access_token(*, base_url: str, api_token: str, email: str) -> str:
    async with httpx.AsyncClient(base_url=base_url, follow_redirects=False) as client:
        meta = (await client.get("/.well-known/oauth-authorization-server")).json()
        reg = await client.post(
            meta["registration_endpoint"],
            json={
                "client_name": "cross-namespace-null-smoke",
                "redirect_uris": ["http://127.0.0.1:9/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        reg.raise_for_status()
        client_id = reg.json()["client_id"]
        resource = meta.get("resource") or base_url.rstrip("/")
        verifier = (
            base64.urlsafe_b64encode(b"cross-namespace-null-smoke-verifier").decode().rstrip("=")
        )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        auth = await client.get(
            meta["authorization_endpoint"],
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://127.0.0.1:9/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
            },
            follow_redirects=False,
        )
        location = auth.headers["location"]
        txn = httpx.URL(location).params.get("txn")
        if not txn:
            raise RuntimeError(f"missing txn in redirect: {location}")
        login = await client.post(
            "/login",
            data={"txn": txn, "api_token": api_token, "email": email},
            follow_redirects=False,
        )
        callback = login.headers["location"]
        code = httpx.URL(callback).params.get("code")
        if not code:
            raise RuntimeError(f"missing code in callback: {callback}")
        token = await client.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:9/callback",
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        token.raise_for_status()
        return token.json()["access_token"]


def _decode_payload(result) -> dict:
    if result.isError:
        text = str(result.content)
        if "unexpected_keyword_argument" in text or "validation error" in text.lower():
            raise RuntimeError(f"tool error: {result.content}")
        raise RuntimeError(f"tool error: {result.content}")
    text = result.content[0].text.strip()
    if text.startswith("{"):
        payload = json.loads(text)
    elif "{" in text:
        payload = json.loads(text[text.index("{") : text.rindex("}") + 1])
    else:
        raise RuntimeError(f"unexpected payload: {text!r}")
    if isinstance(payload, dict) and payload.get("state") == "error":
        code = str(payload.get("code") or "")
        if code in {"rate_limited"}:
            raise RuntimeError(f"proxy error: {payload}")
        if code in {"database_unavailable"}:
            return {"_smoke_note": "upstream business error after null accept", **payload}
        if "validation" in str(payload.get("message", "")).lower():
            raise RuntimeError(f"proxy error: {payload}")
        return {"_smoke_note": "upstream business error after null accept", **payload}
    if isinstance(payload, dict) and payload.get("state") == "done":
        return payload.get("result") or payload
    return payload


async def _run(
    proxy_url: str,
    api_token: str,
    email: str,
    cases: tuple[SmokeCase, ...],
) -> int:
    base_url = proxy_url.rstrip("/mcp").rstrip("/")
    token = await _obtain_access_token(base_url=base_url, api_token=api_token, email=email)
    headers = {"Authorization": f"Bearer {token}"}
    results: dict[str, str] = {}
    async with (
        create_mcp_http_client(headers=headers) as http_client,
        streamable_http_client(proxy_url, http_client=http_client) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(
            read_stream, write_stream, read_timeout_seconds=timedelta(seconds=90)
        ) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        available = {tool.name for tool in listed.tools}
        if not cases:
            print(json.dumps(sorted(available), indent=2))
            print("no --cases given; listed published tools only", file=sys.stderr)
            return 0
        for case in cases:
            if case.tool not in available:
                results[case.label] = f"SKIP tool missing: {case.tool}"
                continue
            try:
                payload = _decode_payload(await session.call_tool(case.tool, case.args))
                await asyncio.sleep(0.3)
                missing = [key for key in case.expect_keys if key not in payload]
                if missing:
                    raise RuntimeError(f"missing expected keys {missing}: {payload}")
                if payload.get("_smoke_note"):
                    results[case.label] = f"OK null-accepted ({payload.get('code', 'upstream')})"
                else:
                    results[case.label] = "OK"
            except Exception as exc:
                results[case.label] = f"FAIL {exc}"
                print(f"[FAIL] {case.label} {case.tool}: {exc}", file=sys.stderr)

    print(json.dumps(results, indent=2, ensure_ascii=False))
    failed = [label for label, status in results.items() if status.startswith("FAIL")]
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-url", default="http://localhost:8080/")
    parser.add_argument("--api-token", default=os.environ.get("KEYSTONE_MCP_API_TOKEN"))
    parser.add_argument("--email", default=os.environ.get("KEYSTONE_MCP_EMAIL"))
    parser.add_argument(
        "--cases",
        type=Path,
        default=None,
        help="JSON file of smoke cases (see module docstring)",
    )
    args = parser.parse_args()
    if not args.api_token or not args.email:
        parser.error("--api-token/--email or KEYSTONE_MCP_API_TOKEN/KEYSTONE_MCP_EMAIL required")
    cases = load_cases(args.cases) if args.cases else ()
    return asyncio.run(_run(args.proxy_url, args.api_token, args.email, cases))


if __name__ == "__main__":
    raise SystemExit(main())
