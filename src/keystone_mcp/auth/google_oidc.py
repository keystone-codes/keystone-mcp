"""Google OIDC login helper: authorize redirect, token exchange, id_token verify."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
OPENID_SCOPE = "openid email"


class GoogleOidcError(Exception):
    """Base error for Google OIDC validation failures."""

    def __init__(self, message: str, *, code: str = "google_oidc_error") -> None:
        super().__init__(message)
        self.code = code


class GoogleTokenExchangeError(GoogleOidcError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="google_token_exchange")


class GoogleIdTokenError(GoogleOidcError):
    def __init__(self, message: str, *, code: str = "google_id_token") -> None:
        super().__init__(message, code=code)


@dataclass(frozen=True, slots=True)
class GoogleVerifiedIdentity:
    email: str
    email_verified: bool
    hosted_domain: str | None = None


@dataclass(frozen=True, slots=True)
class GoogleOidcEndpoints:
    authorization_url: str = GOOGLE_AUTH_URL
    token_url: str = GOOGLE_TOKEN_URL
    jwks_url: str = GOOGLE_JWKS_URL


class GoogleOidcClient:
    """Server-side Google OIDC RP: authorization URL, code exchange, id_token verify."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        endpoints: GoogleOidcEndpoints | None = None,
        timeout: float = 10.0,
        jwks_client: PyJWKClient | None = None,
    ) -> None:
        self._client_id = client_id.strip()
        self._client_secret = client_secret.strip()
        self._redirect_uri = redirect_uri.strip()
        self._endpoints = endpoints or GoogleOidcEndpoints()
        self._timeout = timeout
        self._jwks_client = jwks_client or PyJWKClient(self._endpoints.jwks_url)

    def new_nonce(self) -> str:
        return secrets.token_urlsafe(24)

    def new_pkce_pair(self) -> tuple[str, str]:
        verifier = secrets.token_urlsafe(48)
        import base64
        import hashlib

        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return verifier, challenge

    def build_authorization_url(
        self,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
        hosted_domain: str | None = None,
    ) -> str:
        params = {
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "response_type": "code",
            "scope": OPENID_SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        if hosted_domain:
            domain = hosted_domain.strip().lower().lstrip("@")
            if domain:
                params["hd"] = domain
        return f"{self._endpoints.authorization_url}?{urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "redirect_uri": self._redirect_uri,
            "code_verifier": code_verifier,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(self._endpoints.token_url, data=payload)
        except httpx.HTTPError as exc:
            raise GoogleTokenExchangeError("Google token endpoint request failed") from exc

        if response.status_code != 200:
            error_code: str | None = None
            try:
                error_payload = response.json()
                if isinstance(error_payload, dict):
                    raw_error = error_payload.get("error")
                    if raw_error is not None:
                        error_code = str(raw_error)
            except ValueError:
                pass
            logger.warning(
                "google token exchange failed status=%s error=%s",
                response.status_code,
                error_code,
            )
            raise GoogleTokenExchangeError("Google token endpoint returned an error")

        try:
            body = response.json()
        except ValueError as exc:
            raise GoogleTokenExchangeError("Google token response was not JSON") from exc

        if not isinstance(body, dict) or not body.get("id_token"):
            raise GoogleTokenExchangeError("Google token response missing id_token")
        return body

    def verify_id_token(self, id_token: str, expected_nonce: str) -> GoogleVerifiedIdentity:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=list(GOOGLE_ISSUERS),
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.InvalidIssuerError:
            raise GoogleIdTokenError("id_token issuer is invalid", code="google_iss") from None
        except jwt.InvalidAudienceError:
            raise GoogleIdTokenError("id_token audience is invalid", code="google_aud") from None
        except jwt.ExpiredSignatureError:
            raise GoogleIdTokenError("id_token has expired", code="google_exp") from None
        except jwt.InvalidTokenError as exc:
            raise GoogleIdTokenError("id_token signature or format is invalid") from exc

        iss = claims.get("iss", "")
        if iss not in GOOGLE_ISSUERS:
            raise GoogleIdTokenError("id_token issuer is invalid", code="google_iss")

        token_nonce = claims.get("nonce")
        if not token_nonce or token_nonce != expected_nonce:
            raise GoogleIdTokenError("id_token nonce mismatch", code="google_nonce")

        email = str(claims.get("email", "")).strip().lower()
        if not email or "@" not in email:
            raise GoogleIdTokenError("id_token missing email", code="google_email")

        email_verified = claims.get("email_verified")
        if email_verified is not True:
            raise GoogleIdTokenError("id_token email is not verified", code="google_email_verified")

        azp = claims.get("azp")
        if azp is not None and str(azp) != self._client_id:
            raise GoogleIdTokenError("id_token authorized party mismatch", code="google_azp")

        hd = claims.get("hd")
        hosted_domain = str(hd).strip().lower() if hd else None
        return GoogleVerifiedIdentity(
            email=email,
            email_verified=True,
            hosted_domain=hosted_domain,
        )


def email_matches_allowed_domain(
    email: str,
    allowed_domain: str,
    *,
    hosted_domain: str | None = None,
) -> bool:
    """Workspace domain policy: hd must match; email suffix is an additional check."""
    domain = allowed_domain.strip().lower().lstrip("@")
    if not domain:
        return True

    normalized_hd = hosted_domain.strip().lower() if hosted_domain else ""
    if not normalized_hd or normalized_hd != domain:
        return False

    normalized_email = email.strip().lower()
    return normalized_email.endswith(f"@{domain}")
