"""Human-identity gate: policy-declared tools need an interactive login."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    obtain_access_token,
    register_client,
)
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.human_identity import (
    has_interactive_human_identity,
    requires_human_identity,
)
from keystone_mcp.rbac.policy import parse_policy_yaml
from keystone_mcp.router.rbac_middleware import RbacDenialReason
from keystone_mcp.server import build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.fake_login import FakeFormProvider, FakeRedirectProvider
from support.rbac_conformance import (
    CONFORMANCE_EMAIL,
    DecisionRecorder,
    build_conformance_harness,
    conformance_policy,
)
from test_login_flow_generic import _build_app, _start_redirect

GATED_TOOLS = ("ledger_commit",)
UNGATED_TOOLS = ("ledger_propose", "documents_write", "reports_read")

POLICY_WITHOUT_GATE = """\
version: "no-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""

POLICY_WITH_GLOB_GATE = """\
version: "glob-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
requires_human_identity: ["ledger_*"]
"""


def _identity(auth_method: str, *, interactive: bool) -> VerifiedIdentity:
    return VerifiedIdentity(
        email=CONFORMANCE_EMAIL,
        claims={"email": CONFORMANCE_EMAIL, "auth_method": auth_method, "interactive": interactive},
    )


@pytest.fixture
def patch_api_key_identity(monkeypatch):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: _identity("api_key", interactive=False),
    )


@pytest.fixture
def patch_google_identity(monkeypatch):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: _identity("google", interactive=True),
    )


async def _async_noop(_context):
    return {"ok": True}


# --- unit ------------------------------------------------------------------------


def test_interactive_identity_detection():
    assert has_interactive_human_identity(None) is False
    assert has_interactive_human_identity(VerifiedIdentity(email="a@b.c")) is False
    assert has_interactive_human_identity(_identity("api_key", interactive=False)) is False
    assert has_interactive_human_identity(_identity("google", interactive=True)) is True


def test_legacy_token_without_interactive_claim():
    """A token minted before 0.5.0 carries only auth_method -- the fallback

    rule in ``has_interactive_human_identity`` must still open the gate for
    "google" and keep it closed for "api_key", exactly as the pre-0.5.0
    string comparison did, until these tokens expire (see the function's
    0.6.0-removal note).
    """
    legacy_google = VerifiedIdentity(
        email=CONFORMANCE_EMAIL, claims={"email": CONFORMANCE_EMAIL, "auth_method": "google"}
    )
    legacy_api_key = VerifiedIdentity(
        email=CONFORMANCE_EMAIL, claims={"email": CONFORMANCE_EMAIL, "auth_method": "api_key"}
    )
    assert has_interactive_human_identity(legacy_google) is True
    assert has_interactive_human_identity(legacy_api_key) is False


def test_requires_human_identity_reads_the_policy():
    policy = conformance_policy()
    assert policy.requires_human_identity("ledger_commit") is True
    assert policy.requires_human_identity("ledger_propose") is False
    assert requires_human_identity("ledger_commit", policy) is True
    assert requires_human_identity("ledger_propose", policy) is False


def test_requires_human_identity_without_a_policy_is_false():
    assert requires_human_identity("ledger_commit", None) is False


def test_gate_supports_globs():
    policy = parse_policy_yaml(POLICY_WITH_GLOB_GATE)
    assert policy.requires_human_identity("ledger_commit") is True
    assert policy.requires_human_identity("ledger_read") is True
    assert policy.requires_human_identity("reports_read") is False


def test_absent_section_gates_nothing():
    policy = parse_policy_yaml(POLICY_WITHOUT_GATE)
    assert policy.human_identity_patterns == ()
    assert policy.requires_human_identity("ledger_commit") is False


# --- middleware ------------------------------------------------------------------


@pytest.mark.parametrize("tool", GATED_TOOLS)
@pytest.mark.asyncio
async def test_gated_tool_denied_for_machine_identity(patch_api_key_identity, tool: str):
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)

    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.HUMAN_IDENTITY_REQUIRED


@pytest.mark.parametrize("tool", GATED_TOOLS)
@pytest.mark.asyncio
async def test_gated_tool_allowed_for_interactive_identity(patch_google_identity, tool: str):
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.parametrize("tool", UNGATED_TOOLS)
@pytest.mark.asyncio
async def test_ungated_tool_allows_machine_identity(patch_api_key_identity, tool: str):
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_gate_comes_from_the_policy_file_not_from_code(
    patch_api_key_identity,
    tmp_path,
):
    """The same tool passes with no requires_human_identity section."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY_WITHOUT_GATE, encoding="utf-8")
    harness = build_conformance_harness(
        roles=("administrator",),
        policy_path=policy_path,
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_yaml_declared_gate_is_enforced_by_the_middleware(
    patch_api_key_identity,
    tmp_path,
):
    """A tool gated only by YAML (never named in code) is refused."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """\
version: "yaml-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
requires_human_identity: ["documents_write"]
""",
        encoding="utf-8",
    )
    harness = build_conformance_harness(roles=("administrator",), policy_path=policy_path)
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "documents_write"})())

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.HUMAN_IDENTITY_REQUIRED

    # A tool outside the gate still passes under the same identity.
    other = MiddlewareContext(message=type("Msg", (), {"name": "documents_read"})())
    assert await harness.middleware.on_call_tool(other, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_gate_applies_after_the_allow_check(patch_api_key_identity):
    """A role that cannot reach the tool is denied as not permitted, not as ungated."""
    harness = build_conformance_harness(roles=("viewer",))
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.NOT_PERMITTED


# --- end-to-end: the interactive claim comes from the provider, not its name -----
#
# These drive a real sign-in through KeystoneOAuthProvider (not a patched
# identity) to prove the whole chain: LoginProvider.interactive ->
# _complete_login -> the access token's "interactive" claim ->
# has_interactive_human_identity -> the RBAC gate.


async def test_interactive_oidc_provider_opens_human_tools(monkeypatch):
    """A redirect provider named "okta" (not "google") still opens gated tools.

    Only its own ``interactive=True`` makes this so -- the pre-0.5.0 code
    trusted the literal name "google"; this provider's name is deliberately
    something else.
    """
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(CONFORMANCE_EMAIL, roles=("operator",))
    okta = FakeRedirectProvider("okta", interactive=True)
    app, settings, oauth = _build_app([okta], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            redirect_response = await _start_redirect(client, txn, "okta")
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]
            callback = await client.get(
                "/login/okta/callback",
                params={"state": state, "code": "x", "email": CONFORMANCE_EMAIL},
            )
            assert callback.status_code == 302, callback.text
            code = parse_qs(urlparse(callback.headers["location"]).query)["code"][0]
            token_resp = await client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": client_id,
                    "code_verifier": _verifier,
                    "resource": settings.resource_url,
                },
            )

    assert token_resp.status_code == 200, token_resp.text
    access = await oauth.load_access_token(token_resp.json()["access_token"])
    assert access is not None
    assert access.claims["auth_method"] == "okta"
    assert access.claims["interactive"] is True
    assert (
        has_interactive_human_identity(
            VerifiedIdentity(email=CONFORMANCE_EMAIL, claims=access.claims)
        )
        is True
    )

    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=CONFORMANCE_EMAIL, claims=access.claims),
    )
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


async def test_api_key_login_does_not_open_human_tools(monkeypatch):
    """A real api_key sign-in's token carries interactive=False and is denied."""
    settings = Settings(base_url=BASE_URL)
    idp = StaticIdentityProvider({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, _registry, oauth, *_rest = build_server(
        identity_provider=idp, settings=settings, oauth_store=store
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            res = await obtain_access_token(client, settings.resource_url, email=CONFORMANCE_EMAIL)
    assert res["status"] == 200, res
    access = await oauth.load_access_token(res["body"]["access_token"])
    assert access is not None
    assert access.claims["interactive"] is False

    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=access.subject or "", claims=access.claims),
    )
    harness = build_conformance_harness(roles=("administrator",))
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())
    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.HUMAN_IDENTITY_REQUIRED


async def test_provider_named_google_but_not_interactive_is_refused():
    """A form provider literally named "google" must not inherit Google's trust.

    ``login/factory.py`` normally refuses to register any provider but the
    built-in ``GoogleLoginProvider`` under the name "google"; this bypasses
    that factory-level guard to check the defense at its real source:
    ``KeystoneOAuthProvider`` must derive ``interactive`` from the provider's
    own ``LoginProvider.interactive`` property, never from its name matching
    "google".
    """
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    fake_google_form = FakeFormProvider("google")
    assert fake_google_form.interactive is False
    provider = KeystoneOAuthProvider(settings, store, pending, login_providers=[fake_google_form])

    client = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=[REDIRECT_URI],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(client)
    params = AuthorizationParams(
        state="s",
        scopes=[],
        code_challenge="c",
        redirect_uri=REDIRECT_URI,
        redirect_uri_provided_explicitly=True,
        resource=None,
    )
    redirect_url = await provider.authorize(client, params)
    txn_id = parse_qs(urlparse(redirect_url).query)["txn"][0]

    identity = await fake_google_form.verify({"email": "alice@example.com"})
    response = await provider._complete_login(
        txn_id, identity, "en", auth_method="google", interactive=fake_google_form.interactive
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    auth_code = await provider.load_authorization_code(client, code)
    assert auth_code is not None
    token = await provider.exchange_authorization_code(client, auth_code)
    access = await store.get_access_token(token.access_token)
    assert access is not None
    assert access.claims["auth_method"] == "google"
    assert access.claims["interactive"] is False
    assert (
        has_interactive_human_identity(
            VerifiedIdentity(email="alice@example.com", claims=access.claims)
        )
        is False
    )
