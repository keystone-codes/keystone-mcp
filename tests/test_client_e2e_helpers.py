"""Unit tests for scripts/client_e2e_helpers.py (login HTML and callback parsing)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HELPERS_PATH = REPO_ROOT / "scripts" / "client_e2e_helpers.py"
SNAPSHOT_DIR = Path(__file__).resolve().parent / "data" / "login-pages"


def _load_helpers():
    spec = importlib.util.spec_from_file_location("client_e2e_helpers", HELPERS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


helpers = _load_helpers()


def test_parse_api_key_login_form_from_consent_snapshot() -> None:
    html = (SNAPSHOT_DIR / "consent-en.html").read_text(encoding="utf-8")
    action, fields = helpers.parse_api_key_login_form(
        html,
        page_url="http://localhost:8080/login?txn=TXN",
    )
    assert action == "http://localhost:8080/login"
    assert fields["txn"] == "TXN"
    assert "email" not in fields or fields.get("email") == ""


def test_parse_oauth_callback_location_extracts_code_and_state() -> None:
    redirect_uri = "http://127.0.0.1:18765/callback"
    location = (
        "http://127.0.0.1:18765/callback?code=abc123&state=xyz"
    )
    code, state = helpers.parse_oauth_callback_location(
        location,
        redirect_uri=redirect_uri,
        expected_state="xyz",
    )
    assert code == "abc123"
    assert state == "xyz"


def test_parse_oauth_callback_location_rejects_wrong_state() -> None:
    with pytest.raises(ValueError, match="state mismatch"):
        helpers.parse_oauth_callback_location(
            "http://127.0.0.1:9/callback?code=c&state=bad",
            redirect_uri="http://127.0.0.1:9/callback",
            expected_state="good",
        )


def test_parse_api_key_login_form_missing_form_raises() -> None:
    with pytest.raises(ValueError, match="no POST /login form"):
        helpers.parse_api_key_login_form("<html><body>no form</body></html>", page_url="http://x/")
