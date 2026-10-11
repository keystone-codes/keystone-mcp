"""IdentityProvider — the authorization backend behind the MCP OAuth server.

Authorization is delegated to whatever backend a deployment configures: an
external auth service over HTTP introspection, or a static set of dev tokens.
This module isolates that choice behind a small protocol so the OAuth provider
never imports a concrete backend and either can be swapped without touching the
OAuth provider or the router.

The api_token is validated **at the OAuth authorization step**: an invalid token
means no authorization code is ever issued. The verified email becomes a claim
on the issued access token and is propagated downstream as ``X-Author-Email``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class IdentityProvider(Protocol):
    """Validates connection credentials and yields a verified identity.

    Implementations must treat the api_token as a secret (never log it) and
    return the verified email only when the token is currently valid.
    """

    async def verify(self, api_token: str, email: str) -> bool:
        """Return True iff *api_token* is a currently-valid credential.

        The email is the user identity asserted at login; on success it is bound
        to the issued access token as a verified claim.
        """
        ...


class StaticIdentityProvider:
    """Config/dev IdentityProvider backed by a fixed set of valid tokens.

    Used for local development and as the default test double. Production swaps
    this for an auth-service introspection client (or a thin adapter over the
    keystone ``api_key_service`` registry) without changing the OAuth provider.
    """

    def __init__(self, valid_tokens: set[str] | None = None) -> None:
        self._valid_tokens = set(valid_tokens or [])

    async def verify(self, api_token: str, email: str) -> bool:
        if not api_token or not email or "@" not in email:
            return False
        return api_token in self._valid_tokens


class AuthServiceIdentityProvider:
    """Production IdentityProvider backed by keystone auth-service introspection."""

    def __init__(self, base_url: str, service_token: str, *, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._service_token = service_token
        self._timeout = timeout

    async def verify(self, api_token: str, email: str) -> bool:
        if not api_token or not email or "@" not in email:
            return False
        if not self._base_url or not self._service_token:
            return False

        import httpx

        url = f"{self._base_url}/api/internal/apikey/introspect"
        headers = {"Authorization": f"Bearer {self._service_token}"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    url,
                    json={"api_token": api_token},
                    headers=headers,
                )
                response.raise_for_status()
                payload = response.json()
        except Exception:
            return False

        if not payload.get("valid"):
            return False
        registry_email = (payload.get("email") or "").strip().lower()
        if not registry_email:
            return False
        return registry_email == email.strip().lower()
