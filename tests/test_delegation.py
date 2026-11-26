"""Role-grant delegation, and POST /auth/delegate."""

from __future__ import annotations

import json
import logging
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import httpx2
import jwt
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from mcp.server.auth.provider import AccessToken

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, validate_settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.server import bootstrap_rbac_policy, build_server
from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.user_directory.types import (
    ApiKeyRecord,
    ApiKeyVerification,
    IssuedApiKey,
    generate_api_key_material,
    subject_type_of,
)
from keystone_mcp.user_directory.util import normalize_email
from support.admin_harness import build_delegation_harness, run_admin_tool
from support.login import dev_token_login
from support.oauth_harness import BASE_URL
from support.test_env import UNUSED_REDIS_URL


@pytest.mark.asyncio
async def test_delegate_grants_roles_within_own_rights(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_add",
        {"email": "new@corp.example", "full_name": "New", "roles": ["reader"]},
        hr,
    )
    assert out["state"] == "done"
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "m@corp.example", "role": "reader"},
        hr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_delegate_cannot_grant_roles_beyond_own_rights(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    bob_before = await h["directory"].resolve_user("bob@corp.example")
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "finance"},
        hr,
    )
    assert out.get("code") == "forbidden"
    assert "finance" in out.get("message", "")
    bob_after = await h["directory"].resolve_user("bob@corp.example")
    assert bob_after.roles == bob_before.roles
    out = await run_admin_tool(
        h,
        "users_add",
        {"email": "wide@corp.example", "full_name": "Wide", "roles": ["docsplus"]},
        hr,
    )
    assert out.get("code") == "forbidden"
    assert "docsplus" in out.get("message", "")


@pytest.mark.asyncio
async def test_set_roles_checks_only_added_roles(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_set_roles",
        {"email": "m@corp.example", "roles": ["finance", "reader"]},
        hr,
    )
    assert out["state"] == "done"
    out = await run_admin_tool(
        h,
        "users_set_roles",
        {"email": "m@corp.example", "roles": ["docsplus"]},
        hr,
    )
    assert out.get("code") == "forbidden"
    assert "docsplus" in out.get("message", "")


@pytest.mark.asyncio
async def test_revoke_is_not_limited(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_revoke_role",
        {"email": "m@corp.example", "role": "finance"},
        hr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_unpublished_service_needs_the_literal_pattern(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "crm"},
        hr,
    )
    assert out.get("code") == "forbidden"
    crmhr = VerifiedIdentity(email="crmhr@corp.example")
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "crm"},
        crmhr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_full_administrator_grants_anything(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    admin = VerifiedIdentity(email="a1@corp.example")
    for role in ("finance", "docsplus", "crm"):
        out = await run_admin_tool(
            h,
            "users_grant_role",
            {"email": "bob@corp.example", "role": role},
            admin,
        )
        assert out["state"] == "done", role


@pytest.mark.asyncio
async def test_service_account_roles_follow_the_same_rule(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    sam = VerifiedIdentity(email="sam@corp.example")
    await h["directory"].create_user(
        email="sam@corp.example",
        full_name="Sam",
        roles=["sam"],
        note=None,
        actor="system:test",
    )
    out = await run_admin_tool(
        h,
        "service_accounts_add",
        {"name": "bot-reader", "roles": ["reader"]},
        sam,
    )
    assert out["state"] == "done"
    out = await run_admin_tool(
        h,
        "service_accounts_add",
        {"name": "bot-finance", "roles": ["finance"]},
        sam,
    )
    assert out.get("code") == "forbidden"
    assert "finance" in out.get("message", "")


@pytest.mark.asyncio
async def test_delegation_refusal_is_audited_and_counted(tmp_path: Path) -> None:
    observability = MagicMock()
    h = await build_delegation_harness(tmp_path, observability=observability)
    hr = VerifiedIdentity(email="hr@corp.example")
    await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "finance"},
        hr,
    )
    observability.record_users_mutation.assert_called()
    assert observability.record_users_mutation.call_args.kwargs["code"] == "forbidden"
    observability.record_admin_refusal.assert_called_with(
        operation="users_grant_role",
        reason="delegation",
    )


@pytest.mark.asyncio
async def test_one_directory_lookup_per_role_check(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    directory = h["directory"]
    original = directory.resolve_user
    counter = {"n": 0}

    async def counting_resolve(subject: str):
        counter["n"] += 1
        return await original(subject)

    directory.resolve_user = counting_resolve  # type: ignore[method-assign]
    hr = VerifiedIdentity(email="hr@corp.example")
    await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "reader"},
        hr,
    )
    assert counter["n"] == 2


pytestmark = pytest.mark.asyncio

AUDIT_SALT = "delegation-audit-salt"
PERSON = "anna@example.com"
ACTOR = "svc:demo"
FORM_RESOURCE = "https://mcp.platform.example/mcp"
ISSUER = "keystone-platform"


class KeyedMemoryDirectory(InMemoryUserDirectory):
    """In-memory directory plus API keys, so the exchange can verify ``ksk_``."""

    def __init__(self, unavailable: bool = False) -> None:
        super().__init__(unavailable=unavailable)
        self._keys: dict[str, ApiKeyVerification] = {}

    @property
    def capabilities(self) -> frozenset[str]:
        return super().capabilities | frozenset({"api_keys"})

    async def issue_api_key(
        self,
        *,
        subject: str,
        label: str | None,
        expires_in_days: int | None,
        actor: str,
    ) -> IssuedApiKey:
        del expires_in_days
        key_id, _secret, full = generate_api_key_material()
        kind = subject_type_of(subject)
        canonical = subject.strip().lower() if kind == "service" else normalize_email(subject)
        now = datetime.now(UTC)
        record = ApiKeyRecord(
            key_id=key_id,
            subject=canonical,
            label=label,
            created_at=now,
            created_by=actor,
            expires_at=None,
            revoked_at=None,
            revoked_by=None,
        )
        self._keys[full] = ApiKeyVerification(
            key_id=key_id,
            subject=canonical,
            subject_type=kind,
            expires_at=None,
        )
        return IssuedApiKey(record=record, key=full)

    async def list_api_keys(
        self,
        *,
        subject: str | None = None,
        include_revoked: bool = False,
    ) -> list[ApiKeyRecord]:
        del subject, include_revoked
        return []

    async def revoke_api_key(self, *, key_id: str, actor: str) -> tuple[ApiKeyRecord, bool]:
        del actor
        raise KeyError(key_id)

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None:
        if self.unavailable:
            raise OSError("users directory unavailable")
        return self._keys.get(key)


def _public_pem(key: EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def _write_issuers(
    directory: Path,
    public_pem: str,
    *,
    actors: list[str] | None = None,
    modes: list[str] | None = None,
    extra_issuer_key: bool = False,
) -> Path:
    key_path = directory / "keystone-platform.pub.pem"
    key_path.write_text(public_pem, encoding="utf-8")
    issuer: dict[str, object] = {
        "public_key_file": str(key_path),
        "actors": ["svc:demo"] if actors is None else actors,
    }
    if modes is not None:
        issuer["modes"] = modes
    if extra_issuer_key:
        issuer["unexpected"] = "no"
    document = {"version": 1, "issuers": {ISSUER: issuer}}
    path = directory / "issuers.yaml"
    # The delivery file is YAML. Write it the same way, without a key in the text
    # of the issuers file itself.
    lines = [
        "version: 1",
        "issuers:",
        f"  {ISSUER}:",
        f"    public_key_file: {key_path}",
        "    actors:",
    ]
    for actor in issuer["actors"]:  # type: ignore[union-attr]
        lines.append(f"      - {actor}")
    if modes is not None:
        rendered = ", ".join(modes)
        lines.append(f"    modes: [{rendered}]")
    if extra_issuer_key:
        lines.append("    unexpected: no")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    del document
    return path


def _settings(tmp_path: Path, issuers: Path, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "base_url": BASE_URL,
        "refresh_interval_seconds": 0,
        "redis_url": "",
        "users_db_url": f"sqlite:///{tmp_path / 'users.db'}",
        "deployment_profile": "local",
        "rbac_mode": "off",
        "rbac_audit_subject_salt": AUDIT_SALT,
        "delegation_enabled": True,
        "delegation_issuers_file": str(issuers),
        "delegation_token_ttl_seconds": 300,
    }
    base.update(overrides)
    return Settings(**base)


def _resolver(directory: KeyedMemoryDirectory) -> CachedUserDirectoryResolver:
    cache = ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=30)
    return CachedUserDirectoryResolver(
        directory,
        revision_reader=InMemoryRevisionReader(),
        cache=cache,
        circuit_breaker=CircuitBreaker(failure_threshold=3, recovery_seconds=30),
        api_key_cache=ApiKeyVerificationCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
    )


def _sign(
    private_key: EllipticCurvePrivateKey,
    claims: dict[str, object],
    *,
    alg: str = "ES256",
    typ: str = "keystone-delegation+jwt",
) -> str:
    headers = {"typ": typ, "kid": "not-a-thumbprint"}
    if alg == "none":
        return jwt.encode(claims, key=None, algorithm="none", headers=headers)
    return jwt.encode(claims, private_key, algorithm=alg, headers=headers)


def _claims(
    *,
    aud: str,
    mode: str = "person",
    sub: str | None = PERSON,
    include_sub: bool = True,
    iat: float | None = None,
    exp: float | None = None,
    iss: str = ISSUER,
    extra: Mapping[str, object] | None = None,
) -> dict[str, object]:
    now = int(time.time())
    payload: dict[str, object] = {
        "iss": iss,
        "aud": aud,
        "iat": now if iat is None else iat,
        "exp": now + 30 if exp is None else exp,
        "jti": str(uuid.uuid4()),
        "kst_mode": mode,
        "kst_client": "keystone-web",
        "kst_project": "demo",
        "kst_session": "sess-1",
    }
    if include_sub and sub is not None:
        payload["sub"] = sub
    if extra:
        payload.update(extra)
    return payload


@dataclass
class Harness:
    client: httpx.AsyncClient
    settings: Settings
    store: InMemoryOAuthStore
    oauth: object
    directory: KeyedMemoryDirectory
    private_key: EllipticCurvePrivateKey
    app: object
    service_key: str

    def assertion(self, **kwargs: object) -> tuple[str, dict[str, object]]:
        payload: dict[str, object] = {"aud": self.settings.base_url}
        payload.update(kwargs)
        claims = _claims(**payload)  # type: ignore[arg-type]
        return _sign(self.private_key, claims), claims

    async def exchange(
        self,
        token: str,
        *,
        actor_token: str | None = None,
        resource: str = FORM_RESOURCE,
        content_type: str | None = None,
        raw: bytes | None = None,
    ) -> httpx.Response:
        if raw is not None:
            return await self.client.post(
                "/auth/delegate",
                content=raw,
                headers={"content-type": content_type or "application/json"},
            )
        return await self.client.post(
            "/auth/delegate",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor_token": actor_token if actor_token is not None else self.service_key,
                "actor_token_type": "urn:keystone:params:oauth:token-type:api-key",
                "resource": resource,
            },
        )


@asynccontextmanager
async def _harness(
    tmp_path: Path,
    *,
    modes: list[str] | None = None,
    settings_overrides: dict[str, object] | None = None,
    person_roles: tuple[str, ...] = ("keystone-member", "mcp-analyst"),
    actor_roles: tuple[str, ...] = (),
    block_person: bool = False,
    seed_person: bool = True,
    block_actor: bool = False,
    with_policy: Path | None = None,
    prepare: object | None = None,
) -> AsyncIterator[tuple[Harness, object]]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    issuers = _write_issuers(tmp_path, _public_pem(private_key), modes=modes)
    overrides = dict(settings_overrides or {})
    if with_policy is not None:
        overrides.update(
            rbac_mode="enforce",
            rbac_policy_path=str(with_policy),
        )
    settings = _settings(tmp_path, issuers, **overrides)
    directory = KeyedMemoryDirectory()
    if seed_person:
        directory.seed(PERSON, roles=person_roles, is_blocked=block_person)
    await directory.create_service_account(
        name="demo",
        description=None,
        roles=list(actor_roles),
        actor="ops@example.com",
    )
    if block_actor:
        await directory.update_service_account(
            name="demo", is_blocked=True, actor="ops@example.com"
        )
    issued = await directory.issue_api_key(
        subject=ACTOR,
        label="project",
        expires_in_days=None,
        actor="ops@example.com",
    )
    resolver = _resolver(directory)
    store = InMemoryOAuthStore()
    mcp, registry, oauth, _upstreams, policy_manager, *_rest = build_server(
        settings=settings,
        oauth_store=store,
        user_resolver=resolver,
        user_directory=directory,
        login_providers=[dev_token_login({"dev-token"})],
        register_builtin_catalog=False,
    )
    if prepare is not None:
        prepare(registry, policy_manager)  # type: ignore[operator]
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield (
                Harness(
                    client=client,
                    settings=settings,
                    store=store,
                    oauth=oauth,
                    directory=directory,
                    private_key=private_key,
                    app=app,
                    service_key=issued.key,
                ),
                registry,
            )


def _audit_events(caplog: pytest.LogCaptureFixture, name: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for record in caplog.records:
        if not record.message.startswith("rbac audit "):
            continue
        payload = json.loads(record.message.removeprefix("rbac audit "))
        if payload.get("event") == name:
            events.append(payload)
    return events


async def test_route_missing_when_disabled(tmp_path: Path) -> None:
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        redis_url="",
        users_db_url=f"sqlite:///{tmp_path / 'users.db'}",
        deployment_profile="local",
        rbac_mode="off",
        delegation_enabled=False,
    )
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({"dev-token"})],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            response = await client.post("/auth/delegate", data={"grant_type": "x"})
    assert response.status_code == 404


async def test_person_token(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    async with _harness(tmp_path) as (harness, _registry):
        token, _claims_body = harness.assertion()
        response = await harness.exchange(token)
        assert response.status_code == 200
        body = response.json()
        assert body["access_token"].startswith("km_at_")
        assert body["expires_in"] == 300
        assert body["token_type"] == "Bearer"
        assert "refresh_token" not in body
        loaded = await harness.oauth.load_access_token(body["access_token"])
        assert loaded is not None
        again = await harness.oauth.load_access_token(body["access_token"])
        assert again is not None
        assert loaded.subject == PERSON
        assert loaded.claims["act"]["sub"] == ACTOR
        assert loaded.claims["interactive"] is False
        assert loaded.claims["auth_method"] == "delegation"
        assert loaded.claims["email"] == PERSON
        assert loaded.resource == harness.settings.resource_url
        assert loaded.resource != FORM_RESOURCE
        assert loaded.client_id == "keystone-delegation"
        assert loaded.scopes == []
    events = _audit_events(caplog, "delegation_exchange")
    assert events[-1]["outcome"] == "issued"
    assert events[-1]["reason"] is None
    assert events[-1]["subject"] == hash_subject(PERSON, salt=AUDIT_SALT)
    assert events[-1]["actor"] == hash_subject(ACTOR, salt=AUDIT_SALT)
    assert PERSON not in json.dumps(events[-1])


def _denied(response: httpx.Response, code: str) -> None:
    assert response.status_code == 400
    body = response.json()
    assert body == {"error": "invalid_grant", "error_description": code}


def _mcp_transport(harness: Harness, token: str) -> StreamableHttpTransport:
    app = harness.app

    def factory(headers=None, timeout=None, auth=None, **_kw):  # noqa: ANN001
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=BASE_URL,
            headers=headers,
            timeout=timeout or httpx2.Timeout(30.0),
            auth=auth,
            follow_redirects=True,
        )

    return StreamableHttpTransport(
        harness.settings.transport_url,
        auth=token,
        httpx_client_factory=factory,
    )


def _prepare_union(registry, policy_manager) -> None:  # noqa: ANN001
    registry.add_route("deleg_ping", StubAdapter(), mode="live", description="Person tool.")
    registry.add_route("deleg_analyst", StubAdapter(), mode="live", description="Second role.")
    registry.add_route("deleg_actor", StubAdapter(), mode="live", description="Actor only.")
    bootstrap_rbac_policy(policy_manager, registry)


async def test_person_rbac_is_union_of_roles(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """\
version: "1.0.0"
default_deny: true
roles:
  keystone-member:
    allow: ["deleg_ping"]
  mcp-analyst:
    allow: ["deleg_analyst"]
  actor-only:
    allow: ["deleg_actor"]
requires_human_identity: []
critical_tools: []
""",
        encoding="utf-8",
    )
    caplog.set_level(logging.INFO)
    async with _harness(
        tmp_path,
        with_policy=policy,
        person_roles=("keystone-member", "mcp-analyst"),
        actor_roles=("actor-only",),
        prepare=_prepare_union,
    ) as (harness, _registry):
        token, _claims_body = harness.assertion()
        issued = await harness.exchange(token)
        assert issued.status_code == 200
        access = issued.json()["access_token"]
        async with Client(_mcp_transport(harness, access)) as client:
            allowed = await client.call_tool("deleg_ping", {})
            assert allowed.data["state"] == "done"
            second = await client.call_tool("deleg_analyst", {})
            assert second.data["state"] == "done"
            with pytest.raises(ToolError, match="access denied"):
                await client.call_tool("deleg_actor", {})

        decisions = [
            event
            for event in _audit_events(caplog, "rbac_authz_decision")
            if event.get("tool") == "deleg_ping" and event.get("operation") == "call_tool"
        ]
        assert decisions[-1]["actor"] == hash_subject(ACTOR, salt=AUDIT_SALT)
        assert decisions[-1]["delegation_jti"]

        ordinary = f"km_at_{secrets.token_urlsafe(32)}"
        await harness.store.put_access_token(
            AccessToken(
                token=ordinary,
                client_id="ordinary-client",
                scopes=[],
                expires_at=int(time.time()) + 300,
                resource=harness.settings.resource_url,
                subject=PERSON,
                claims={
                    "auth_method": "oauth",
                    "subject_type": "human",
                    "email": PERSON,
                    "interactive": True,
                },
            )
        )
        before = len(_audit_events(caplog, "rbac_authz_decision"))
        async with Client(_mcp_transport(harness, ordinary)) as client:
            ordinary_result = await client.call_tool("deleg_ping", {})
            assert ordinary_result.data["state"] == "done"
        fresh = _audit_events(caplog, "rbac_authz_decision")[before:]
        ordinary_decisions = [
            event
            for event in fresh
            if event.get("tool") == "deleg_ping" and event.get("operation") == "call_tool"
        ]
        assert ordinary_decisions
        assert "actor" not in ordinary_decisions[-1]


async def test_service_without_sub(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        token, _claims_body = harness.assertion(
            mode="service",
            include_sub=False,
            extra={
                "kst_requested_by": "owner@example.com",
                "kst_requested_by_verified": False,
            },
        )
        response = await harness.exchange(token)
        assert response.status_code == 200
        loaded = await harness.oauth.load_access_token(response.json()["access_token"])
        assert loaded is not None
        assert loaded.subject == ACTOR
        assert loaded.claims["subject_type"] == "service"
        assert loaded.claims["requested_by"] == "owner@example.com"
        assert loaded.claims["requested_by_verified"] is False
        assert loaded.claims["act"]["sub"] == ACTOR


async def test_service_sub_must_match_actor(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        matching, _claims_body = harness.assertion(mode="service", sub=ACTOR)
        ok = await harness.exchange(matching)
        assert ok.status_code == 200
        loaded = await harness.oauth.load_access_token(ok.json()["access_token"])
        assert loaded is not None
        assert loaded.subject == ACTOR

        before = len(harness.store._access_tokens)  # noqa: SLF001
        foreign, _claims_body = harness.assertion(mode="service", sub="other@example.com")
        refused = await harness.exchange(foreign)
        _denied(refused, "actor_mismatch")
        assert len(harness.store._access_tokens) == before  # noqa: SLF001


async def test_bad_signature(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        other = ec.generate_private_key(ec.SECP256R1())
        claims = _claims(aud=harness.settings.base_url)
        token = _sign(other, claims)
        _denied(await harness.exchange(token), "bad_signature")


async def test_unknown_issuer(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        claims = _claims(aud=harness.settings.base_url, iss="someone-else")
        token = _sign(harness.private_key, claims)
        _denied(await harness.exchange(token), "bad_signature")


async def test_bad_audience(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        token, _claims_body = harness.assertion(aud="https://other.example")
        _denied(await harness.exchange(token), "bad_audience")


async def test_expired(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        now = time.time()
        token, _claims_body = harness.assertion(iat=now - 40, exp=now - 10)
        _denied(await harness.exchange(token), "expired")


async def test_ttl_over_60s(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        now = time.time()
        token, _claims_body = harness.assertion(iat=now, exp=now + 90)
        _denied(await harness.exchange(token), "assertion_ttl")


async def test_replay(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        token, _claims_body = harness.assertion()
        first = await harness.exchange(token)
        assert first.status_code == 200
        _denied(await harness.exchange(token), "replay")


async def test_human_key_refused(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        human = await harness.directory.issue_api_key(
            subject=PERSON,
            label="person",
            expires_in_days=None,
            actor="ops@example.com",
        )
        token, _claims_body = harness.assertion()
        _denied(await harness.exchange(token, actor_token=human.key), "actor_not_service")


async def test_unknown_actor(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        other = await harness.directory.issue_api_key(
            subject="svc:other",
            label="other",
            expires_in_days=None,
            actor="ops@example.com",
        )
        token, _claims_body = harness.assertion()
        _denied(await harness.exchange(token, actor_token=other.key), "unknown_actor")


async def test_actor_blocked(tmp_path: Path) -> None:
    async with _harness(tmp_path, block_actor=True) as (harness, _registry):
        token, _claims_body = harness.assertion()
        _denied(await harness.exchange(token), "actor_blocked")


async def test_subject_unknown(tmp_path: Path) -> None:
    async with _harness(tmp_path, seed_person=False) as (harness, _registry):
        token, _claims_body = harness.assertion()
        _denied(await harness.exchange(token), "subject_unknown")


async def test_subject_blocked(tmp_path: Path) -> None:
    async with _harness(tmp_path, block_person=True) as (harness, _registry):
        token, _claims_body = harness.assertion()
        _denied(await harness.exchange(token), "subject_blocked")


async def test_directory_down_does_not_burn_jti(tmp_path: Path) -> None:
    async with _harness(tmp_path) as (harness, _registry):
        token, _claims_body = harness.assertion()
        harness.directory.unavailable = True
        down = await harness.exchange(token)
        assert down.status_code == 503
        assert down.json()["error"] == "temporarily_unavailable"
        assert harness.store._access_tokens == {}  # noqa: SLF001
        harness.directory.unavailable = False
        recovered = await harness.exchange(token)
        assert recovered.status_code == 200


async def test_redis_down_when_configured_is_503(tmp_path: Path) -> None:
    async with _harness(
        tmp_path,
        settings_overrides={
            "redis_url": "redis://[::1]:1/0",
            "users_backend": "http",
            "rbac_mode": "off",
        },
    ) as (harness, _registry):
        token, _claims_body = harness.assertion()
        response = await harness.exchange(token)
        assert response.status_code == 503
        assert response.json()["error"] == "temporarily_unavailable"
        assert harness.store._access_tokens == {}  # noqa: SLF001


async def test_no_secrets_in_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    async with _harness(tmp_path) as (harness, _registry):
        other = ec.generate_private_key(ec.SECP256R1())
        bad = _sign(other, _claims(aud=harness.settings.base_url))
        denied = await harness.exchange(bad)
        _denied(denied, "bad_signature")
        good, _claims_body = harness.assertion()
        issued = await harness.exchange(good)
        assert issued.status_code == 200
        text = caplog.text
        assert harness.service_key not in text
        assert "km_at_" not in text
        assert "eyJ" not in text
        assert "BEGIN" not in text
        assert "eyJ" not in denied.text


async def test_startup_refuses_bad_file(tmp_path: Path) -> None:
    def settings(**overrides: object) -> Settings:
        base: dict[str, object] = {
            "base_url": "http://127.0.0.1:8080",
            "deployment_profile": "local",
            "redis_url": UNUSED_REDIS_URL,
            "rbac_mode": "off",
            "delegation_enabled": False,
            "delegation_issuers_file": "",
            "delegation_token_ttl_seconds": 300,
        }
        base.update(overrides)
        return Settings(**base)

    validate_settings(settings())

    for ttl in (0, 901):
        with pytest.raises(ConfigError, match="KEYSTONE_MCP_DELEGATION_TOKEN_TTL_SECONDS"):
            validate_settings(settings(delegation_token_ttl_seconds=ttl))

    missing = tmp_path / "missing.yaml"
    with pytest.raises(ConfigError, match="cannot be read"):
        validate_settings(settings(delegation_enabled=True, delegation_issuers_file=str(missing)))

    bad_key = ec.generate_private_key(ec.SECP384R1())
    issuers = _write_issuers(tmp_path, _public_pem(bad_key))
    with pytest.raises(ConfigError, match="P-256") as caught:
        validate_settings(settings(delegation_enabled=True, delegation_issuers_file=str(issuers)))
    assert "BEGIN" not in str(caught.value)
