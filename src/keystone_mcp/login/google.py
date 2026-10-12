"""``GoogleLoginProvider`` — Google OIDC sign-in exposed as a ``LoginProvider``.

Wraps :class:`~keystone_mcp.auth.google_oidc.GoogleOidcClient` (authorization
URL construction, authorization-code exchange, ``id_token`` verification)
behind the ``RedirectLoginProvider`` shape. Keystone itself handles the OAuth
transaction, the ``state``/CSRF binding and the users-directory lookup; this
provider only proves that the browser completed a Google sign-in for a given,
email-verified address.
"""

from __future__ import annotations

from collections.abc import Mapping

from keystone_mcp.auth.google_oidc import (
    GoogleIdTokenError,
    GoogleOidcClient,
    GoogleOidcError,
    GoogleTokenExchangeError,
    email_matches_allowed_domain,
)
from keystone_mcp.login.protocol import LoginIdentity, LoginKind, LoginRedirect, LoginRejected
from keystone_mcp.user_directory.util import normalize_email


class GoogleLoginProvider:
    """Google as a ``redirect``-kind :class:`~keystone_mcp.login.protocol.LoginProvider`."""

    def __init__(self, client: GoogleOidcClient, *, allowed_domain: str = "") -> None:
        self._client = client
        self._allowed_domain = allowed_domain.strip()

    @property
    def name(self) -> str:
        return "google"

    @property
    def kind(self) -> LoginKind:
        return "redirect"

    @property
    def title(self) -> str:
        return "Google"

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def begin(self, *, state: str, callback_url: str) -> LoginRedirect:
        # callback_url is not used here: this GoogleOidcClient was built with
        # its redirect_uri already fixed (settings.google_redirect_uri), so
        # Google is always told to return to the deployment's one registered
        # address regardless of which name this provider instance is given.
        del callback_url
        nonce = self._client.new_nonce()
        verifier, challenge = self._client.new_pkce_pair()
        url = self._client.build_authorization_url(
            state=state,
            nonce=nonce,
            code_challenge=challenge,
            hosted_domain=self._allowed_domain or None,
        )
        return LoginRedirect(url=url, attempt={"nonce": nonce, "verifier": verifier})

    async def complete(
        self, *, params: Mapping[str, str], callback_url: str, attempt: Mapping[str, str]
    ) -> LoginIdentity:
        del callback_url
        if params.get("error"):
            raise LoginRejected("request_invalid", "google returned an error")
        code = params.get("code", "").strip()
        if not code:
            raise LoginRejected("request_invalid", "missing authorization code")

        nonce = attempt.get("nonce", "")
        verifier = attempt.get("verifier", "")
        try:
            token_body = await self._client.exchange_code(code, verifier)
            identity = self._client.verify_id_token(str(token_body["id_token"]), nonce)
        except (GoogleTokenExchangeError, GoogleIdTokenError, GoogleOidcError) as exc:
            raise LoginRejected("identity_invalid", str(exc)) from exc

        email = normalize_email(identity.email)
        if self._allowed_domain and not email_matches_allowed_domain(
            email, self._allowed_domain, hosted_domain=identity.hosted_domain
        ):
            raise LoginRejected("domain_not_allowed", "google account outside allowed domain")

        return LoginIdentity(email=email, provider="google", interactive=True)
