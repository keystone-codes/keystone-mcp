"""RSA JWKS fixtures and fake Google OIDC endpoints for login tests."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keystone_mcp.auth.google_oidc import GoogleOidcClient, GoogleOidcEndpoints


@dataclass(frozen=True, slots=True)
class GoogleOidcTestKeys:
    private_key_pem: bytes
    public_key: object
    public_jwks: dict[str, Any]
    kid: str
    client_id: str


def generate_google_test_keys(client_id: str = "test-google-client") -> GoogleOidcTestKeys:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    kid = "test-key-1"
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }
    return GoogleOidcTestKeys(
        private_key_pem=private_pem,
        public_key=public_key,
        public_jwks={"keys": [jwk]},
        kid=kid,
        client_id=client_id,
    )


def int_to_base64url(value: int) -> str:
    import base64

    width = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(width, "big")).rstrip(b"=").decode()


class FakePyJWKClient:
    """Minimal stand-in for PyJWKClient backed by a static public key."""

    def __init__(self, public_key: object, jwks: dict[str, Any]) -> None:
        self._public_key = public_key
        self._jwks = jwks

    def get_signing_key_from_jwt(self, token: str) -> Any:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        for jwk_dict in self._jwks["keys"]:
            if jwk_dict.get("kid") == kid:
                return type("SigningKey", (), {"key": self._public_key})()
        raise jwt.InvalidTokenError("signing key not found")


def sign_google_id_token(
    keys: GoogleOidcTestKeys,
    *,
    email: str,
    nonce: str,
    email_verified: bool = True,
    hd: str | None = None,
    iss: str = "https://accounts.google.com",
    expired: bool = False,
    wrong_aud: bool = False,
    wrong_nonce: str | None = None,
    azp: str | None = None,
    algorithm: str = "RS256",
    signing_key: bytes | str | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": iss,
        "aud": "wrong-aud" if wrong_aud else keys.client_id,
        "sub": "google-subject-123",
        "email": email,
        "email_verified": email_verified,
        "nonce": wrong_nonce if wrong_nonce is not None else nonce,
        "iat": now,
        "exp": now - 60 if expired else now + 3600,
    }
    if hd is not None:
        payload["hd"] = hd
    if azp is not None:
        payload["azp"] = azp
    key = signing_key if signing_key is not None else keys.private_key_pem
    headers: dict[str, str] = {}
    if algorithm == "RS256":
        headers["kid"] = keys.kid
    return jwt.encode(payload, key, algorithm=algorithm, headers=headers)


@dataclass
class MockGoogleOidc:
    keys: GoogleOidcTestKeys
    client: GoogleOidcClient
    token_calls: list[dict[str, str]]
    last_nonce: str | None = None
    last_email: str | None = None
    last_id_token: str | None = None
    last_verifier: str | None = None

    async def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        self.token_calls.append({"code": code, "code_verifier": code_verifier})
        self.last_verifier = code_verifier
        if self.last_id_token is None:
            raise RuntimeError("pending Google identity not set for mock token exchange")
        return {
            "id_token": self.last_id_token,
            "access_token": "google-at",
            "token_type": "Bearer",
        }

    def set_pending_identity(
        self,
        *,
        email: str,
        nonce: str,
        email_verified: bool = True,
        hd: str | None = None,
        iss: str = "https://accounts.google.com",
        expired: bool = False,
        wrong_aud: bool = False,
        wrong_nonce: str | None = None,
        azp: str | None = None,
        algorithm: str = "RS256",
        signing_key: bytes | str | None = None,
    ) -> str:
        self.last_nonce = nonce
        self.last_email = email.strip().lower()
        self.last_id_token = sign_google_id_token(
            self.keys,
            email=email,
            nonce=nonce,
            email_verified=email_verified,
            hd=hd,
            iss=iss,
            expired=expired,
            wrong_aud=wrong_aud,
            wrong_nonce=wrong_nonce,
            azp=azp,
            algorithm=algorithm,
            signing_key=signing_key,
        )
        return self.last_id_token


def build_mock_google_oidc(
    redirect_uri: str,
    *,
    client_id: str = "test-google-client",
    client_secret: str = "test-google-secret",
) -> MockGoogleOidc:
    keys = generate_google_test_keys(client_id=client_id)
    jwk_client = FakePyJWKClient(keys.public_key, keys.public_jwks)
    client = GoogleOidcClient(
        client_id,
        client_secret,
        redirect_uri,
        endpoints=GoogleOidcEndpoints(
            authorization_url="https://mock.google/auth",
            token_url="https://mock.google/token",
            jwks_url="https://mock.google/jwks",
        ),
        jwks_client=jwk_client,
    )
    mock = MockGoogleOidc(keys=keys, client=client, token_calls=[])
    client.exchange_code = mock.exchange_code  # type: ignore[method-assign]
    return mock
