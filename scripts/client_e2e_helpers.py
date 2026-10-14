"""Pure helpers for scripts/client_e2e.py (browser-style OAuth login HTML parsing)."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse


class _LoginFormFields(HTMLParser):
    """Collect the first POST form whose action targets the API-key login path."""

    def __init__(self) -> None:
        super().__init__()
        self._in_form = False
        self._form_depth = 0
        self.action: str | None = None
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "form" and not self._in_form:
            method = (attr.get("method") or "get").lower()
            action = attr.get("action") or ""
            if method == "post" and action.rstrip("/").endswith("/login"):
                self._in_form = True
                self._form_depth = 1
                self.action = action
            return
        if not self._in_form:
            return
        if tag == "form":
            self._form_depth += 1
        elif tag == "input":
            name = attr.get("name")
            if not name:
                return
            input_type = (attr.get("type") or "text").lower()
            if input_type in {"submit", "button", "image"}:
                return
            self.fields[name] = attr.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if not self._in_form:
            return
        if tag == "form":
            self._form_depth -= 1
            if self._form_depth == 0:
                self._in_form = False


def parse_api_key_login_form(html: str, *, page_url: str) -> tuple[str, dict[str, str]]:
    """Return absolute form action and field map from a consent/login HTML page."""
    parser = _LoginFormFields()
    parser.feed(html)
    if parser.action is None:
        raise ValueError("no POST /login form found in HTML")
    action = urljoin(page_url, parser.action)
    if "txn" not in parser.fields:
        raise ValueError("login form is missing hidden txn field")
    return action, dict(parser.fields)


def parse_oauth_callback_location(
    location: str,
    *,
    redirect_uri: str,
    expected_state: str | None = None,
) -> tuple[str, str]:
    """Extract authorization ``code`` and ``state`` from a redirect Location header."""
    parsed = urlparse(location)
    redirect = urlparse(redirect_uri)
    if parsed.scheme != redirect.scheme or parsed.netloc != redirect.netloc:
        raise ValueError(f"callback location {location!r} is not on redirect URI {redirect_uri!r}")
    qs = parse_qs(parsed.query)
    code = qs.get("code", [None])[0]
    state = qs.get("state", [None])[0]
    if not code:
        raise ValueError(f"callback location has no code: {location!r}")
    if not state:
        raise ValueError(f"callback location has no state: {location!r}")
    if expected_state is not None and state != expected_state:
        raise ValueError(f"state mismatch: expected {expected_state!r}, got {state!r}")
    return code, state


def tool_result_text(result) -> str:
    """Flatten MCP CallToolResult text blocks for assertions."""
    chunks: list[str] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            chunks.append(text)
    return "\n".join(chunks)


def summarize_clients_md_row(
    *,
    sdk_version: str,
    protocol_label: str,
    sign_in: str,
    refresh: str,
    tools: str,
    list_changed: str,
    progress: str,
    cancel: str,
    elicitation: str,
) -> str:
    """One-line summary for pasting into docs/clients.md."""
    return (
        f"mcp-python-sdk {sdk_version} | {protocol_label} | sign-in {sign_in} | "
        f"refresh {refresh} | tools {tools} | list_changed {list_changed} | "
        f"progress {progress} | cancel {cancel} | elicitation {elicitation}"
    )


def normalize_html_for_tests(html: str) -> str:
    """Match login-page snapshot normalization in tests/test_login_pages.py."""
    return re.sub(r">\s+<", "><", html.strip())
