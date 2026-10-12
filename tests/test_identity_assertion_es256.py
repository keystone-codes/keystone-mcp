"""ES256 identity assertions and published JWKS (Y11)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import httpx2
import jwt
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastmcp import Client, FastMCP
from fastmcp.utilities.tests import asgi_server

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, validate_settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.identity_assertion import (
    IDENTITY_JWKS_PATH,
    IDENTITY_TYP,
    IdentityAssertionSigner,
    build_identity_jwks,
    ec_public_key_jwk_thumbprint,
    load_ec_p256_private_key,
)
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.server import build_server
from keystone_mcp.upstream_registry.load import parse_upstream_entry
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import auth_field_errors, validate_upstream_registry
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATH = REPO_ROOT / "examples" / "keystone-identity" / "python" / "keystone_identity.py"
ES256_VECTOR_PATH = REPO_ROOT / "examples" / "keystone-identity" / "test-vector-es256.json"

FIXED_ES256_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAASNFZ4kKvN7xI0
VniQq83vEjRWeJCrze8SNFZ4kKuhRANCAASz4IlGK3RL3RBRnQF+nI0mGeh5oUm9
0Nw9WnsV7MhcHuDOfAtt6zB8ntgq44aZEiUDMF99mUUG5VgYkbtTBVOC
-----END PRIVATE KEY-----"""

FIXED_ES256_KID = "-qn2Lrjkz9irbI5rft_XNCtt_5gGTKtzmhEGzVokNWA"

BASE_URL = "http://localhost:8080"

ANN = VerifiedIdentity(email="ann@example.com", claims={"auth_method": "google"})


@pytest.fixture
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


@pytest.fixture
def permissive_policy() -> UpstreamSecurityPolicy:
    return UpstreamSecurityPolicy(allow_insecure_http=True, egress_allow_private=True)


def _load_reference() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_identity_ref_es256", REFERENCE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def reference() -> ModuleType:
    return _load_reference()


@pytest.fixture(scope="module")
def es256_vector() -> dict:
    return json.loads(ES256_VECTOR_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def es256_signing_pem(monkeypatch) -> str:
    private_key = ec_mod.generate_private_key(SECP256R1())
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(
        "utf-8"
    )
    monkeypatch.setenv("KEYSTONE_MCP_IDENTITY_SIGNING_KEY", pem)
    return pem


def test_kid_is_rfc7638_thumbprint():
    private_key = load_ec_p256_private_key(FIXED_ES256_PEM)
    assert ec_public_key_jwk_thumbprint(private_key.public_key()) == FIXED_ES256_KID


async def test_es256_assertion_verifies_with_published_jwks(
    monkeypatch, es256_signing_pem, patch_verified_identity
):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["whoami"], observed=observed)
    async with LifespanManager(app):
        settings = Settings(base_url=BASE_URL, identity_signing_key=es256_signing_pem)
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
            identity_issuer=settings.base_url.rstrip("/"),
            _identity_signing_key_pem=settings.identity_signing_key,
        )
        upstreams.add_upstream(
            "hello-upstream",
            UPSTREAM_MCP_URL,
            namespace="hello",
            identity_alg="ES256",
        )
        await upstreams.discover_all()

        async with Client(main) as client:
            await client.call_tool_mcp("hello_whoami", {})

        token = observed["headers"].get("x-keystone-identity")
        assert token is not None
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "ES256"
        assert header["typ"] == IDENTITY_TYP
        assert header.get("kid")

    idp = StaticIdentityProvider(set())
    store = InMemoryOAuthStore()
    mcp, *_rest = build_server(
        identity_provider=idp,
        settings=Settings(
            base_url=BASE_URL,
            refresh_interval_seconds=0,
            identity_signing_key=es256_signing_pem,
            upstreams_json=json.dumps(
                [
                    {
                        "name": "hello-upstream",
                        "url": "http://unused.example/mcp",
                        "namespace": "hello",
                        "enabled": False,
                        "auth": {"identity_alg": "ES256"},
                    }
                ]
            ),
        ),
        oauth_store=store,
    )
    async with asgi_server(mcp, path="/") as running:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=running.app),
            base_url=BASE_URL,
            headers={"Host": "localhost:8080"},
        ) as client:
            jwks_resp = await client.get(IDENTITY_JWKS_PATH)
        assert jwks_resp.status_code == 200
        assert jwks_resp.headers.get("cache-control") == "public, max-age=300"
        jwks = jwks_resp.json()
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["alg"] == "ES256"

        signing_key = jwt.PyJWK.from_dict(jwks["keys"][0]).key
        decoded = jwt.decode(
            token,
            signing_key,
            algorithms=["ES256"],
            audience="hello-upstream",
            issuer=settings.base_url.rstrip("/"),
        )
        assert decoded["mcp_target"] == "whoami"


async def test_jwks_404_without_key():
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0)
    idp = StaticIdentityProvider(set())
    store = InMemoryOAuthStore()
    mcp, *_rest = build_server(identity_provider=idp, settings=settings, oauth_store=store)
    async with asgi_server(mcp, path="/") as running:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=running.app),
            base_url=BASE_URL,
            headers={"Host": "localhost:8080"},
        ) as client:
            resp = await client.get(IDENTITY_JWKS_PATH)
        assert resp.status_code == 404


@pytest.mark.parametrize(
    "pem",
    [
        "not-a-pem",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_bad_signing_key_is_refused(pem):
    settings = Settings(deployment_profile="local", identity_signing_key=pem)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_IDENTITY_SIGNING_KEY"):
        validate_settings(settings)


def test_bad_signing_key_p384_refused():
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP384R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    settings = Settings(deployment_profile="local", identity_signing_key=pem)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_IDENTITY_SIGNING_KEY"):
        validate_settings(settings)


def test_registry_identity_alg_and_secret_are_exclusive(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs",
                "url": "http://docs.example/mcp",
                "namespace": "docs",
                "auth": {
                    "identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET",
                    "identity_alg": "ES256",
                },
            }
        ],
    }
    messages = validate_upstream_registry(document, policy=permissive_policy)
    assert any("identity_secret_env (HS256)" in m for m in messages)


def test_es256_entry_without_key_refuses_start(monkeypatch, permissive_policy):
    monkeypatch.delenv("KEYSTONE_MCP_IDENTITY_SIGNING_KEY", raising=False)
    item = {
        "name": "docs",
        "url": "http://docs.example/mcp",
        "namespace": "docs",
        "auth": {"identity_alg": "ES256"},
    }
    with pytest.raises(ValueError, match="KEYSTONE_MCP_IDENTITY_SIGNING_KEY"):
        parse_upstream_entry(item, policy=permissive_policy, check_environment=True)


def test_python_reference_verifies_es256_vector(reference, es256_vector):
    private_key = load_ec_p256_private_key(FIXED_ES256_PEM)
    jwks_payload = build_identity_jwks(private_key)

    def _fake_fetch(_self) -> dict:
        assert _self.uri.endswith("keystone-identity-jwks.json")
        return jwks_payload

    with patch.object(jwt.PyJWKClient, "fetch_data", _fake_fetch):
        identity = reference.verify_keystone_identity(
            es256_vector["token"],
            jwks_url="http://localhost:8080/.well-known/keystone-identity-jwks.json",
            audience=es256_vector["audience"],
            issuer=es256_vector["issuer"],
            algorithms=["ES256"],
            leeway=10**12,
        )
    assert identity.sub == es256_vector["claims"]["sub"]
    assert identity.roles == tuple(es256_vector["claims"]["roles"])


def test_auth_field_errors_rejects_unknown_identity_alg():
    errors = auth_field_errors({"identity_alg": "RS256"})
    assert any("must be ES256" in message for message in errors)


def test_es256_signer_includes_kid_header():
    private_key = load_ec_p256_private_key(FIXED_ES256_PEM)
    kid = ec_public_key_jwk_thumbprint(private_key.public_key())
    signer = IdentityAssertionSigner(
        audience="hello",
        issuer="http://localhost:8080",
        private_key=private_key,
        kid=kid,
    )
    human = VerifiedIdentity(email="ann@example.com", claims={"auth_method": "google"})
    token = signer.sign(
        identity=human,
        task_id="t1",
        mcp_method="tools/call",
        mcp_target="whoami",
        timeout_seconds=60,
        rbac_mode="off",
        now=1_700_000_000,
    )
    header = jwt.get_unverified_header(token)
    assert header["kid"] == FIXED_ES256_KID
    assert header["alg"] == "ES256"
