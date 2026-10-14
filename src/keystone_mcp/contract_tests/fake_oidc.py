"""In-process fake OIDC issuer for tests and extension authors."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlencode, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from keystone_mcp.login.oidc import OidcProviderConfig


@dataclass
class FakeUser:
    email: str = "alice@example.com"
    email_verified: bool = True
    hd: str | None = None
    groups: list[str] = field(default_factory=list)
    extra_claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeTamper:
    unavailable: bool = False
    wrong_nonce: bool = False
    bad_signature: bool = False
    wrong_issuer: str | None = None
    wrong_audience: bool = False
    expired: bool = False
    alg_hs256: bool = False
    token_endpoint_status: int | None = None
    discovery_status: int | None = None
    discovery_issuer: str | None = None
    discovery_authorization_endpoint: str | None = None
    discovery_token_endpoint: str | None = None
    discovery_jwks_uri: str | None = None
    rotate_key: bool = False

    def reset(self) -> None:
        self.unavailable = False
        self.wrong_nonce = False
        self.bad_signature = False
        self.wrong_issuer = None
        self.wrong_audience = False
        self.expired = False
        self.alg_hs256 = False
        self.token_endpoint_status = None
        self.discovery_status = None
        self.discovery_issuer = None
        self.discovery_authorization_endpoint = None
        self.discovery_token_endpoint = None
        self.discovery_jwks_uri = None
        self.rotate_key = False


def _int_to_base64url(value: int) -> str:
    width = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(width, "big")).rstrip(b"=").decode()


class FakeOidcIssuer:
    def __init__(
        self,
        *,
        issuer: str = "https://idp.test",
        client_id: str = "keystone-test",
        client_secret: str = "test-secret",
        alg: str = "RS256",
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.alg = alg
        self.user = FakeUser()
        self.tamper = FakeTamper()
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._public_key = self._private_key.public_key()
        self._kid = "fake-1"
        self._alt_private_key: rsa.RSAPrivateKey | None = None
        self._alt_kid = "fake-2"
        self._pending: dict[str, dict[str, str]] = {}
        self._used_codes: set[str] = set()
        self.app = Starlette(
            routes=[
                Route("/.well-known/openid-configuration", self._discovery, methods=["GET"]),
                Route("/jwks", self._jwks, methods=["GET"]),
                Route("/authorize", self._authorize, methods=["GET"]),
                Route("/token", self._token, methods=["POST"]),
            ]
        )

    def http_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url=self.issuer,
        )

    def config(self, *, name: str = "fake", **overrides: Any) -> OidcProviderConfig:
        """Build ``OidcProviderConfig`` for tests and extension authors.

        Custom redirect providers that do not subclass ``OidcLoginProvider`` need
        only ``issuer``, ``client_id``, ``client_secret``, and an HTTP client factory.
        """
        base = {
            "name": name,
            "title": name.title(),
            "issuer": self.issuer,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        base.update(overrides)
        return OidcProviderConfig(**base)

    async def authorize(self, url: str) -> dict[str, str]:
        """Follow an authorization URL in-process and return callback query params."""
        parsed = urlparse(url)
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": parsed.path or "/authorize",
                "query_string": parsed.query.encode(),
                "headers": [],
            }
        )
        response = await self._authorize(request)
        if not isinstance(response, RedirectResponse):
            raise RuntimeError(f"expected redirect, got {response}")
        location = str(response.headers.get("location", ""))
        callback = urlparse(location)
        return {k: v[0] for k, v in parse_qs(callback.query).items()}

    def _jwks_dict(self) -> dict[str, Any]:
        pub = self._public_key.public_numbers()
        keys = [
            {
                "kty": "RSA",
                "kid": self._kid,
                "use": "sig",
                "alg": self.alg,
                "n": _int_to_base64url(pub.n),
                "e": _int_to_base64url(pub.e),
            }
        ]
        if self._alt_private_key is not None:
            alt_pub = self._alt_private_key.public_key().public_numbers()
            keys.append(
                {
                    "kty": "RSA",
                    "kid": self._alt_kid,
                    "use": "sig",
                    "alg": self.alg,
                    "n": _int_to_base64url(alt_pub.n),
                    "e": _int_to_base64url(alt_pub.e),
                }
            )
        return {"keys": keys}

    async def _discovery(self, request: Request) -> Response:
        del request
        if self.tamper.unavailable:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        if self.tamper.discovery_status is not None:
            return JSONResponse({"error": "unavailable"}, status_code=self.tamper.discovery_status)
        issuer = self.tamper.discovery_issuer or self.issuer
        authorization_endpoint = (
            self.tamper.discovery_authorization_endpoint or f"{self.issuer}/authorize"
        )
        token_endpoint = self.tamper.discovery_token_endpoint or f"{self.issuer}/token"
        jwks_uri = self.tamper.discovery_jwks_uri or f"{self.issuer}/jwks"
        return JSONResponse(
            {
                "issuer": issuer,
                "authorization_endpoint": authorization_endpoint,
                "token_endpoint": token_endpoint,
                "jwks_uri": jwks_uri,
                "id_token_signing_alg_values_supported": [self.alg],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
            }
        )

    async def _jwks(self, request: Request) -> Response:
        del request
        if self.tamper.unavailable:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        return JSONResponse(self._jwks_dict())

    async def _authorize(self, request: Request) -> Response:
        params = request.query_params
        if params.get("client_id") != self.client_id:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if params.get("response_type") != "code":
            return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
        if params.get("code_challenge_method") != "S256":
            return JSONResponse({"error": "invalid_request"}, status_code=400)

        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")
        nonce = params.get("nonce", "")
        code_challenge = params.get("code_challenge", "")
        code = secrets.token_urlsafe(16)
        self._pending[code] = {
            "redirect_uri": redirect_uri,
            "nonce": nonce,
            "code_challenge": code_challenge,
        }
        query = urlencode({"code": code, "state": state})
        return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)

    def _verify_client_auth(self, request: Request, form: dict[str, str]) -> bool:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
            except (ValueError, IndexError):
                return False
            parts = decoded.split(":", 1)
            if len(parts) != 2:
                return False
            cid = unquote_plus(parts[0])
            secret = unquote_plus(parts[1])
            return cid == self.client_id and secret == self.client_secret
        cid = form.get("client_id", "")
        secret = form.get("client_secret", "")
        return cid == self.client_id and secret == self.client_secret

    def _pkce_valid(self, verifier: str, challenge: str) -> bool:
        derived = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return derived == challenge

    async def _token(self, request: Request) -> Response:
        if self.tamper.unavailable:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        if self.tamper.token_endpoint_status is not None:
            return JSONResponse(
                {"error": "temporarily_unavailable"},
                status_code=self.tamper.token_endpoint_status,
            )

        form = dict(await request.form())
        form_str = {str(k): str(v) for k, v in form.items()}
        if not self._verify_client_auth(request, form_str):
            return JSONResponse({"error": "invalid_client"}, status_code=401)

        code = form_str.get("code", "")
        redirect_uri = form_str.get("redirect_uri", "")
        verifier = form_str.get("code_verifier", "")
        pending = self._pending.get(code)
        if pending is None or code in self._used_codes:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if pending["redirect_uri"] != redirect_uri:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if not self._pkce_valid(verifier, pending["code_challenge"]):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        self._used_codes.add(code)
        id_token = self._mint_id_token(pending["nonce"])
        return JSONResponse(
            {
                "access_token": "fake-access",
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 300,
            }
        )

    def _mint_id_token(self, nonce: str) -> str:
        now = int(time.time())
        iss = self.tamper.wrong_issuer or self.issuer
        token_nonce = "wrong" if self.tamper.wrong_nonce else nonce
        payload: dict[str, Any] = {
            "iss": iss,
            "aud": "wrong-aud" if self.tamper.wrong_audience else self.client_id,
            "sub": "fake-subject",
            "email": self.user.email,
            "nonce": token_nonce,
            "iat": now,
            "exp": now - 60 if self.tamper.expired else now + 3600,
        }
        if "email_verified" in self.user.extra_claims:
            payload["email_verified"] = self.user.extra_claims["email_verified"]
        else:
            payload["email_verified"] = self.user.email_verified
        if self.user.hd is not None:
            payload["hd"] = self.user.hd
        if self.user.groups:
            payload["groups"] = list(self.user.groups)
        for key, value in self.user.extra_claims.items():
            if key != "email_verified":
                payload[key] = value

        if self.tamper.alg_hs256:
            return jwt.encode(payload, "hs-secret", algorithm="HS256")

        if (self.tamper.rotate_key or self.tamper.bad_signature) and self._alt_private_key is None:
            self._alt_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if self.tamper.bad_signature and self._alt_private_key is not None:
            key = self._alt_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            kid = self._kid
        elif self.tamper.rotate_key and self._alt_private_key is not None:
            key = self._alt_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            kid = self._alt_kid
        else:
            key = self._private_pem
            kid = self._kid

        return jwt.encode(payload, key, algorithm=self.alg, headers={"kid": kid})
