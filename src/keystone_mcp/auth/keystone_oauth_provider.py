"""KeystoneOAuthProvider — embedded OAuth 2.1 Authorization + Resource Server.

Implements the full embedded OAuth server pattern on top of FastMCP's
``OAuthProvider`` so Claude can connect as a remote OAuth connector. The provider
emits the discovery/registration/authorize/token endpoints; credentials are
collected on a login page (``/login`` plus one ``/login/{name}`` pair per
configured redirect provider) through the pluggable
:class:`~keystone_mcp.login.protocol.LoginProvider` contract (X03) — this
provider owns the OAuth transaction, the consent screen, the CSRF/browser
binding and the users-directory check; a provider only proves who signed in.
A valid login binds the verified ``email`` to the issued access token as a
claim and ``subject`` — this is the verified identity propagated downstream
as ``X-Author-Email``.

OAuth clients and tokens persist in :class:`~keystone_mcp.auth.oauth_store.OAuthStore`
(Redis in production). Pending login transactions and authorization codes persist in
:class:`~keystone_mcp.auth.login_pending_store.LoginPendingStore` with TTL and
atomic single-use consumption. PKCE (S256) is enforced by the
MCP SDK token handler against ``AuthorizationCode.code_challenge``; Resource
Indicators (RFC 8707) bind the token audience and are checked in ``verify_token``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from urllib.parse import parse_qs, quote, urlencode, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastmcp.server.auth import OAuthProvider
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from keystone_mcp.auth.login_pending_store import LoginPendingStore, normalize_login_key_prefix
from keystone_mcp.auth.oauth_store import (
    CredentialRevokedError,
    KeystoneRefreshToken,
    OAuthStore,
    RefreshTokenAlreadyRotatedError,
    RotationRecord,
    token_digest,
)
from keystone_mcp.auth.throttle import (
    InMemoryLoginFailureLimiter,
    LoginAttemptThrottle,
    LoginFailureLimiter,
    RedisLoginFailureLimiter,
    login_throttle_response,
    peer_host,
    wrap_asgi_with_ip_login_throttle,
)
from keystone_mcp.config import Settings, effective_allowed_hosts, resources_equivalent
from keystone_mcp.http.host_guard import cross_site_origin_refusal
from keystone_mcp.login.pages import FieldView, ProviderView, render_consent_page, render_error_page
from keystone_mcp.login.protocol import (
    FormField,
    FormLoginProvider,
    LoginIdentity,
    LoginProvider,
    LoginRejected,
)
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.user_directory.errors import (
    IdentityBindingConflictError,
    UserDirectoryUnavailableError,
)
from keystone_mcp.user_directory.protocol import (
    ApiKeyStateReader,
    IdentityBindingDirectory,
    UserDirectoryResolver,
)
from keystone_mcp.user_directory.types import subject_type_of
from keystone_mcp.user_directory.util import email_folds_to_ascii, normalize_email

logger = logging.getLogger(__name__)

_NS_PENDING_TXN = "txn"
_NS_AUTH_CODE = "code"
_NS_CODE_USED = "code_used"
_NS_LOGIN_ATTEMPT = "login_attempt"
_NS_REFRESH_AUTH = "refresh_auth"

_GRACE_HMAC_KEY = b"keystone-mcp refresh grace v1"

_REFRESH_NO_RESOLVER_WARNED = False


class RefreshTemporarilyUnavailableError(Exception):
    """Users directory unreachable during refresh; the client should retry."""


class _TokenTemporarilyUnavailableGuard:
    """Map RefreshTemporarilyUnavailableError to a 503 JSON response on /token."""

    def __init__(self, app: object) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def intercept_send(message):  # noqa: ANN001
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, intercept_send)
        except RefreshTemporarilyUnavailableError:
            if response_started:
                raise
            response = JSONResponse(
                status_code=503,
                content={
                    "error": "temporarily_unavailable",
                    "error_description": "users directory is unavailable; retry later",
                },
                headers={"Retry-After": "5", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)


def _grace_encryption_key(old_refresh_token: str) -> bytes:
    return hmac.new(_GRACE_HMAC_KEY, old_refresh_token.encode(), hashlib.sha256).digest()


def _seal_grace(old_refresh_token: str, token: OAuthToken) -> str:
    aes = AESGCM(_grace_encryption_key(old_refresh_token))
    nonce = secrets.token_bytes(12)
    ciphertext = aes.encrypt(nonce, token.model_dump_json().encode(), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip("=")


def _open_grace(old_refresh_token: str, blob: str) -> OAuthToken | None:
    try:
        padded = blob + "=" * (-len(blob) % 4)
        raw = base64.urlsafe_b64decode(padded.encode())
        nonce, ciphertext = raw[:12], raw[12:]
        aes = AESGCM(_grace_encryption_key(old_refresh_token))
        plaintext = aes.decrypt(nonce, ciphertext, None)
        return OAuthToken.model_validate_json(plaintext)
    except Exception:
        return None


@dataclass(frozen=True, slots=True)
class RefreshMeta:
    auth_method: str
    resource: str | None
    interactive: bool
    auth_time: int | None
    key_id: str | None
    key_id_known: bool
    key_expires_at: int | None


def encode_refresh_meta(meta: RefreshMeta) -> str:
    payload: dict[str, object] = {
        "auth_method": meta.auth_method,
        "resource": meta.resource,
        "interactive": meta.interactive,
    }
    if meta.auth_time is not None:
        payload["auth_time"] = meta.auth_time
    if meta.key_id_known:
        payload["key_id"] = meta.key_id
        if meta.key_expires_at is not None:
            payload["key_expires_at"] = meta.key_expires_at
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def parse_refresh_meta(raw: str | None) -> RefreshMeta | None:
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    try:
        data = json.loads(stripped)
    except ValueError:
        data = None
    if isinstance(data, dict):
        auth_method = data.get("auth_method")
        if not isinstance(auth_method, str) or not auth_method:
            return None
        resource = data.get("resource")
        if resource is not None and not isinstance(resource, str):
            resource = None
        if "interactive" in data:
            interactive = data["interactive"] is True
        else:
            interactive = auth_method == "google"
        auth_time_raw = data.get("auth_time")
        auth_time = (
            auth_time_raw
            if isinstance(auth_time_raw, int) and not isinstance(auth_time_raw, bool)
            else None
        )
        key_id_known = "key_id" in data
        key_id = data.get("key_id") if key_id_known else None
        if key_id is not None and not isinstance(key_id, str):
            key_id = None
        key_expires_raw = data.get("key_expires_at")
        key_expires_at = (
            key_expires_raw
            if isinstance(key_expires_raw, int) and not isinstance(key_expires_raw, bool)
            else None
        )
        return RefreshMeta(
            auth_method=auth_method,
            resource=resource,
            interactive=interactive,
            auth_time=auth_time,
            key_id=key_id if key_id_known else None,
            key_id_known=key_id_known,
            key_expires_at=key_expires_at if key_id_known else None,
        )
    auth_method = stripped
    if not auth_method:
        return None
    return RefreshMeta(
        auth_method=auth_method,
        resource=None,
        interactive=auth_method == "google",
        auth_time=None,
        key_id=None,
        key_id_known=False,
        key_expires_at=None,
    )


@dataclass(frozen=True, slots=True)
class _AuthCodeEnvelope:
    code: AuthorizationCode
    auth_method: str
    interactive: bool
    auth_time: int | None
    key_id: str | None
    key_id_known: bool
    key_expires_at: int | None


def _meta_from_envelope(envelope: _AuthCodeEnvelope, resource: str | None) -> RefreshMeta:
    return RefreshMeta(
        auth_method=envelope.auth_method,
        resource=resource,
        interactive=envelope.interactive,
        auth_time=envelope.auth_time,
        key_id=envelope.key_id if envelope.key_id_known else None,
        key_id_known=envelope.key_id_known,
        key_expires_at=envelope.key_expires_at if envelope.key_id_known else None,
    )


def _meta_carry_forward(
    old: RefreshMeta,
    *,
    resource: str | None,
    auth_time: int | None = None,
) -> RefreshMeta:
    resolved_auth_time = old.auth_time if auth_time is None else auth_time
    return RefreshMeta(
        auth_method=old.auth_method,
        resource=resource,
        interactive=old.interactive,
        auth_time=resolved_auth_time,
        key_id=old.key_id if old.key_id_known else None,
        key_id_known=old.key_id_known,
        key_expires_at=old.key_expires_at if old.key_id_known else None,
    )


def _human_access_claims(
    subject: str,
    auth_method: str,
    interactive: bool,
    now: int,
    key_id: str | None,
) -> dict[str, object]:
    claims: dict[str, object] = {
        "email": subject,
        "auth_method": auth_method,
        "interactive": interactive,
        "iat": now,
        "subject_type": subject_type_of(subject),
    }
    if isinstance(key_id, str):
        claims["key_id"] = key_id
    return claims


# Double-submit CSRF cookie for the consent screen's redirect-provider
# button forms (A13; generalized from Google-only in X03). Scoped to the
# /login path and as short-lived as the login transaction it protects.
#
# Over https, the cookie carries the `__Host-` prefix instead (finding #4,
# second review): a browser refuses to even store a `__Host-`-prefixed cookie
# unless it is `Secure`, has `Path=/` and carries no `Domain` attribute — which
# means only this exact origin can ever set it, not a sibling subdomain (e.g.
# one running a service with a weaker cookie policy, or a plain-http
# same-host endpoint able to plant a cookie over the network). Without the
# prefix, "any cookie at least 32 characters long" (the old reuse rule below)
# could be an attacker-planted value the attacker already knows, defeating
# the double-submit check's entire purpose. `__Host-` requires `Path=/`, so
# the unprefixed (`http`, dev/demo) spelling keeps the narrower `/login` path
# it always had; only the https deployment that gets the stronger name also
# gets the broader path the prefix demands.
_CSRF_COOKIE_NAME = "km_login_csrf"
_CSRF_COOKIE_NAME_HOST_PREFIXED = "__Host-km_login_csrf"
_LANG_COOKIE_NAME = "km_lang"
_LANG_COOKIE_NAME_HOST_PREFIXED = "__Host-km_lang"
_LANG_COOKIE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60


def _hash_csrf_cookie(value: str) -> str:
    """SHA-256 of a ``km_login_csrf`` cookie value, hex-encoded.

    Used to bind a redirect provider's ``state`` round trip to the browser
    that started it (finding #1): the hash travels inside the server-side
    pending envelope keyed by ``state``, and is compared against a hash of
    the cookie presented on ``/login/{name}/callback``. A plain equality
    check on secrets of fixed, known length does not need
    ``hmac.compare_digest`` to produce a timing side channel worth caring
    about, but the callers compare these hashes with
    ``secrets.compare_digest`` anyway, for the same reason the CSRF field
    comparison on ``POST /login/{name}`` does.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# Default ports that do not need to be shown next to the host on the consent
# screen's redirect-target line.
_DEFAULT_SCHEME_PORTS: dict[str, int] = {"http": 80, "https": 443}


# Loopback hosts a `http` redirect_uri may use even when a redirect-host
# allowlist is configured (A17 finding #4): `http` elsewhere is refused
# outright, since only a host running on the operator's own machine can be
# trusted not to leak the authorization code over the network in the clear.
_LOOPBACK_REDIRECT_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _redirect_uri_allowed(
    uri: str, allowed_hosts: tuple[str, ...], allowed_scheme_hosts: tuple[str, ...]
) -> bool:
    """Whether ``uri`` is allowed by the redirect-host allowlist (A17).

    An empty allowlist (both tuples empty) means no restriction — the 0.3.1
    behaviour. A non-empty allowlist checks the scheme, not just the host
    (finding #4): a redirect_uri with no parseable host is always refused,
    since it cannot be shown to be on an allowed host.

    - ``https``: the host must be in ``allowed_hosts``. Any host on the list
      may use it.
    - ``http``: the host must be in ``allowed_hosts`` *and* be loopback
      (``localhost``/``127.0.0.1``/``::1``). A plain-http redirect to a
      non-loopback host is refused even if that host is otherwise on the
      list, since `claude.ai` being allowed over `https` says nothing about
      trusting an unencrypted `http://claude.ai/...` redirect.
    - Any other scheme (a native app's custom URI, e.g. `cursor://...`):
      refused unless the exact `scheme://host` pair is in
      ``allowed_scheme_hosts``.
    """
    if not allowed_hosts and not allowed_scheme_hosts:
        return True
    parsed = urlparse(str(uri))
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    scheme = parsed.scheme.lower()
    if scheme == "https":
        return host in allowed_hosts
    if scheme == "http":
        return host in _LOOPBACK_REDIRECT_HOSTS and host in allowed_hosts
    return f"{scheme}://{host}" in allowed_scheme_hosts


def _client_redirect_uris_allowed(
    client: OAuthClientInformationFull,
    allowed_hosts: tuple[str, ...],
    allowed_scheme_hosts: tuple[str, ...],
) -> bool:
    """Whether every one of ``client``'s registered redirect_uris is allowed.

    Used at token-exchange time (finding #3) to catch a client that was
    registered before an allowlist existed, or before it was tightened: such a
    client passed ``register_client``'s check (there was none, or a looser
    one, at the time) and can otherwise keep refreshing its tokens forever.
    An empty ``redirect_uris`` is refused the same way `register_client` would
    refuse registering it today (finding #5).
    """
    if not allowed_hosts and not allowed_scheme_hosts:
        return True
    uris = client.redirect_uris or []
    if not uris:
        return False
    return all(_redirect_uri_allowed(str(uri), allowed_hosts, allowed_scheme_hosts) for uri in uris)


def _replay_body(body: bytes):
    """Build a ``receive`` callable that replays an already-consumed ASGI body once.

    Used by :class:`_AuthorizeRedirectHostGuard`, which must read ``client_id``
    out of a ``POST /authorize`` form body before deciding whether to forward
    the request — and the SDK's own handler still needs to read that same
    body afterwards.
    """
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


_REGISTER_MAX_BODY_BYTES = 16 * 1024
_CLIENT_NAME_MAX_CHARS = 100
_REDIRECT_URIS_MAX = 10
_URI_MAX_CHARS = 2048
_SHORT_FIELD_MAX_CHARS = 255
_SCOPE_MAX_CHARS = 1024
_LIST_FIELD_MAX_ITEMS = 10
_REGISTER_ALLOWED_FIELDS = frozenset(
    {
        "redirect_uris",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types",
        "scope",
        "client_name",
        "client_uri",
        "software_id",
        "software_version",
        "application_type",
    }
)


def _register_metadata_error(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    client_name = payload.get("client_name")
    if client_name is not None:
        if not isinstance(client_name, str) or len(client_name) > _CLIENT_NAME_MAX_CHARS:
            return "client_name is too long"
    client_uri = payload.get("client_uri")
    if client_uri is not None:
        if not isinstance(client_uri, str) or len(client_uri) > _URI_MAX_CHARS:
            return "client_uri is too long"
    redirect_uris = payload.get("redirect_uris")
    if redirect_uris is not None:
        if not isinstance(redirect_uris, list):
            return "redirect_uris is too long"
        if len(redirect_uris) > _REDIRECT_URIS_MAX:
            return "too many redirect_uris"
        for uri in redirect_uris:
            if not isinstance(uri, str) or len(uri) > _URI_MAX_CHARS:
                return "redirect_uri is too long"
    for field in ("grant_types", "response_types"):
        value = payload.get(field)
        if value is None:
            continue
        if not isinstance(value, list) or len(value) > _LIST_FIELD_MAX_ITEMS:
            return f"{field} is too long"
        for item in value:
            if not isinstance(item, str) or len(item) > _SHORT_FIELD_MAX_CHARS:
                return f"{field} is too long"
    scope = payload.get("scope")
    if scope is not None and (not isinstance(scope, str) or len(scope) > _SCOPE_MAX_CHARS):
        return "scope is too long"
    for field in (
        "software_id",
        "software_version",
        "token_endpoint_auth_method",
        "application_type",
    ):
        value = payload.get(field)
        if value is not None and (
            not isinstance(value, str) or len(value) > _SHORT_FIELD_MAX_CHARS
        ):
            return f"{field} is too long"
    return None


def _filter_register_payload(payload: dict[str, object]) -> dict[str, object]:
    return {key: payload[key] for key in _REGISTER_ALLOWED_FIELDS if key in payload}


async def _read_limited_body(receive, max_bytes: int) -> tuple[bytes, bool]:
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        body += chunk
        if len(body) > max_bytes:
            return body, True
        if not message.get("more_body", False):
            break
    return body, False


class _RegisterMetadataGuard:
    """Validate and trim DCR metadata before the MCP SDK registration handler."""

    def __init__(self, app: object, observability: RbacObservability | None) -> None:
        self.app = app
        self._observability = observability

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        content_length_raw = headers.get(b"content-length")
        if content_length_raw is not None:
            try:
                if int(content_length_raw) > _REGISTER_MAX_BODY_BYTES:
                    await self._reject(scope, send, "registration request is too large")
                    return
            except ValueError:
                pass

        body, over_limit = await _read_limited_body(receive, _REGISTER_MAX_BODY_BYTES)
        if over_limit:
            await self._reject(scope, send, "registration request is too large")
            return

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            await self.app(scope, _replay_body(body), send)
            return

        if not isinstance(parsed, dict):
            await self.app(scope, _replay_body(body), send)
            return

        error_description = _register_metadata_error(parsed)
        if error_description is not None:
            await self._reject(scope, send, error_description)
            return

        filtered = _filter_register_payload(parsed)
        filtered_body = json.dumps(filtered).encode("utf-8")
        await self.app(scope, _replay_body(filtered_body), send)

    async def _reject(self, scope, send, error_description: str) -> None:  # noqa: ANN001
        if self._observability is not None:
            self._observability.record_oauth_client_registration(outcome="rejected_metadata")
        response = JSONResponse(
            {"error": "invalid_client_metadata", "error_description": error_description},
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, _replay_body(b""), send)


def _error_redirect_allowed(
    location: str,
    *,
    allowed_hosts: tuple[str, ...],
    allowed_scheme_hosts: tuple[str, ...],
) -> bool:
    parsed = urlparse(location)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if scheme in {"http", "https"} and host in _LOOPBACK_REDIRECT_HOSTS:
        return True
    if allowed_hosts or allowed_scheme_hosts:
        return _redirect_uri_allowed(location, allowed_hosts, allowed_scheme_hosts)
    return False


def _location_has_oauth_error(location: str) -> bool:
    parsed = urlparse(location)
    query = parse_qs(parsed.query, keep_blank_values=True)
    return "error" in query


class _AuthorizeErrorRedirectGuard:
    """Keep SDK authorize error redirects on loopback or allow-listed hosts only."""

    def __init__(self, app: object, settings: Settings, provider: KeystoneOAuthProvider) -> None:
        self.app = app
        self._settings = settings
        self._provider = provider

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        redirect_blocked = False

        async def intercept_send(message):  # noqa: ANN001
            nonlocal redirect_blocked
            if message["type"] == "http.response.start":
                status = message.get("status", 200)
                if status in {302, 303, 307}:
                    headers = dict(message.get("headers") or [])
                    location_raw = headers.get(b"location", b"").decode("latin-1")
                    if location_raw and _location_has_oauth_error(location_raw):
                        allowed = _error_redirect_allowed(
                            location_raw,
                            allowed_hosts=self._settings.oauth_allowed_redirect_hosts,
                            allowed_scheme_hosts=self._settings.oauth_allowed_redirect_scheme_hosts,
                        )
                        if not allowed:
                            redirect_blocked = True
                            host = urlparse(location_raw).hostname or ""
                            logger.warning(
                                "authorize error not redirected: redirect_uri host %s is "
                                "neither loopback nor allowed",
                                host,
                            )
                            lang = _pick_language(
                                request,
                                self._settings.login_default_lang,
                                base_url=self._settings.base_url,
                            )
                            response = self._provider._html_error(
                                request, lang, "error_request", 400
                            )
                            await response(scope, receive, send)
                            return
            if redirect_blocked:
                return
            await send(message)

        await self.app(scope, receive, intercept_send)


class _AuthorizeRedirectHostGuard:
    """Wraps the SDK's ``/authorize`` endpoint so a disallowed client never reaches it.

    ``KeystoneOAuthProvider.authorize`` already refuses a request whose
    ``redirect_uri`` host is outside ``KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS``
    — but only once the SDK's ``AuthorizationHandler.handle`` actually calls it.
    Before that, the handler validates the request's ``scope`` (and a few other
    fields) against the client's own registered metadata, and on a validation
    error (``invalid_scope``, ``invalid_request``, ...) redirects straight to
    the client's registered ``redirect_uri`` with ``error``/``state`` query
    parameters — without ever calling ``provider.authorize()`` (finding #3,
    second review). For a client registered before the allowlist existed, or
    before it was tightened (the same class ``_refuse_if_client_redirect_uris_not_allowed``
    guards at token-exchange time), that is a browser redirect to exactly the
    host this allowlist exists to keep it away from.

    This wraps the route *before* the SDK handler runs: it resolves
    ``client_id`` from the request itself (query string on ``GET``, form body
    on ``POST``) and, if every one of that client's registered redirect_uris
    is allowed, forwards the request unchanged. Otherwise it redirects to
    ``/login/redirect-not-allowed`` directly, the same safe destination
    ``KeystoneOAuthProvider.authorize`` uses, without the SDK ever seeing the
    request. An unknown ``client_id`` (not yet registered, or missing) is left
    for the SDK to reject on its own terms.
    """

    def __init__(self, app: object, store: OAuthStore, settings: Settings) -> None:
        self.app = app
        self._store = store
        self._settings = settings

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        allowed_hosts = self._settings.oauth_allowed_redirect_hosts
        allowed_scheme_hosts = self._settings.oauth_allowed_redirect_scheme_hosts
        if not allowed_hosts and not allowed_scheme_hosts:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        if scope.get("method") == "GET":
            client_id = request.query_params.get("client_id")
            forward_receive = receive
        else:
            raw_body = await request.body()
            form = await request.form()
            client_id = form.get("client_id")
            forward_receive = _replay_body(raw_body)

        if client_id:
            client = await self._store.get_client(str(client_id))
            if client is not None and not _client_redirect_uris_allowed(
                client, allowed_hosts, allowed_scheme_hosts
            ):
                logger.warning(
                    "authorize refused before reaching the SDK handler: client "
                    "%s has a redirect_uri host that is not allowed",
                    client_id,
                )
                response = RedirectResponse(
                    url=f"{self._settings.base_url.rstrip('/')}/login/redirect-not-allowed",
                    status_code=302,
                )
                await response(scope, receive, send)
                return

        await self.app(scope, forward_receive, send)


# Anti-framing and content-restriction headers for every login-page HTML
# response. The login page and the consent screen built on top of it (A13)
# carry the api_token / authorization decision, so a third-party
# site must not be able to render it in a hidden iframe and trick a user into
# clicking through it (clickjacking). ``frame-ancestors 'none'`` and
# ``X-Frame-Options: DENY`` both forbid embedding (the header covers older
# browsers that ignore CSP); ``default-src 'none'`` with no ``script-src``
# means the page cannot run or load anything beyond its inline styles and
# same-origin images. ``Referrer-Policy: no-referrer`` keeps the ``?txn=``
# query string (part of the URL) out of the ``Referer`` sent to Google on the
# federated-login redirect. ``form-action`` is intentionally left out: browsers
# also apply it to the redirect that follows a form submission, and
# ``POST /login`` redirects to the client's own redirect URI (e.g.
# ``https://claude.ai/...`` or ``http://localhost:...``), so restricting it
# here would break sign-in.
_HTML_SECURITY_HEADERS: dict[str, str] = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _html_response(content: str, status_code: int = 200) -> HTMLResponse:
    """Build an HTML login-page response carrying the anti-framing/CSP headers.

    Every HTML response the login page (and the future consent screen) emits
    must go through this helper instead of constructing ``HTMLResponse``
    directly, so the headers above are never accidentally omitted. A fresh
    dict copy is passed per call since ``HTMLResponse`` does not treat its
    ``headers`` argument as immutable.
    """
    return HTMLResponse(content, status_code=status_code, headers=dict(_HTML_SECURITY_HEADERS))


# Login page localization. Language is chosen from the browser ``Accept-Language``
# header (or an explicit ``?lang=`` override); the deployment's
# ``KEYSTONE_MCP_LOGIN_DEFAULT_LANG`` is the fallback when neither matches.
FALLBACK_LANG = "en"
RTL_LANGS = frozenset({"he", "ar"})
TRANSLATIONS: dict[str, dict[str, str]] = {
    "he": {
        "title": "Keystone MCP — התחברות",
        "subtitle": "התחברות לחיבור לקוח לסביבת העבודה.",
        "email_label": "אימייל",
        "token_label": "אסימון API",
        "submit": "אישור",
        "error_invalid": "אסימון API או אימייל שגויים",
        "error_request": "בקשת הרשאה לא חוקית או שפג תוקפה",
        "login_with": "התחברות עם {provider}",
        "error_provider_disabled": "שיטת ההתחברות הזו אינה זמינה",
        "error_provider_identity": "ההתחברות דרך ספק הזהות נכשלה",
        "error_provider_domain": "חשבון זה מחוץ לדומיינים המורשים",
        "error_provider_unverified": 'ספק הזהות לא אישר את כתובת הדוא"ל',
        "error_provider_unavailable": "ספק הזהות אינו זמין. נסו שוב מאוחר יותר",
        "error_user_denied": "המשתמש לא רשום או חסום",
        "error_directory_unavailable": "שירות המשתמשים לא זמין",
        "error_redirect_host": "כתובת החזרה של האפליקציה אינה מורשית",
        "consent_title": "לאשר גישה?",
        "consent_app": "אפליקציה",
        "consent_redirect": "לאחר ההתחברות תועברו אל",
        "consent_unnamed": "אפליקציה ללא שם",
        "consent_warning": "המשיכו רק אם אתם יזמתם את ההתחברות הזו ומזהים את הכתובת שלמעלה.",
        "or_api_key": "או עם מפתח API",
        "token_help": "המפתח מונפק על ידי מנהל המערכת; הוא מוצג פעם אחת בלבד בעת ההנפקה.",
        "error_hint_generic": "חזרו ליישום והתחילו את ההתחברות מחדש.",
        "error_hint_request": "חזרו ליישום והתחילו את ההתחברות מחדש. הקישור תקף לעשר דקות.",
        "error_hint_redirect_host": "כתובת החזרה של היישום לא ברשימת המורשים; פנו למנהל המערכת.",
        "error_code_hint": "אם זה חוזר על עצמו, דווחו למנהל המערכת על הקוד:",
        "lang_switcher_label": "שפה",
    },
    "en": {
        "title": "Keystone MCP — Sign in",
        "subtitle": "Sign in to connect a client to your workspace.",
        "email_label": "Email",
        "token_label": "API token",
        "submit": "Authorize",
        "error_invalid": "Invalid api_token or email",
        "error_request": "Invalid or expired authorization request",
        "login_with": "Sign in with {provider}",
        "error_provider_disabled": "This sign-in method is not available",
        "error_provider_identity": "Sign-in with the identity provider failed",
        "error_provider_domain": "This account is outside the allowed domains",
        "error_provider_unverified": "The identity provider has not confirmed this e-mail address",
        "error_provider_unavailable": "The identity provider is unavailable. Try again later",
        "error_user_denied": "User is not registered or is blocked",
        "error_directory_unavailable": "User directory is unavailable",
        "error_redirect_host": "This application's redirect address is not allowed",
        "consent_title": "Allow access?",
        "consent_app": "Application",
        "consent_redirect": "After sign-in you will be sent to",
        "consent_unnamed": "Unnamed application",
        "consent_warning": (
            "Continue only if you started this connection yourself and recognise the address above."
        ),
        "or_api_key": "or with an API key",
        "token_help": "Your administrator issues the key; it is shown only once when created.",
        "error_hint_generic": "Go back to the application and start sign-in again.",
        "error_hint_request": (
            "Go back to the application and start sign-in again. The link is valid for ten minutes."
        ),
        "error_hint_redirect_host": (
            "This application's return address is not on the allowed list; contact your administrator."
        ),
        "error_code_hint": "If this keeps happening, tell your administrator the code:",
        "lang_switcher_label": "Language",
    },
    "ru": {
        "title": "Keystone MCP — Вход",
        "subtitle": "Вход для подключения клиента к рабочему пространству.",
        "email_label": "Электронная почта",
        "token_label": "API-токен",
        "submit": "Авторизовать",
        "error_invalid": "Неверный api_token или email",
        "error_request": "Недействительный или истёкший запрос авторизации",
        "login_with": "Войти через {provider}",
        "error_provider_disabled": "Этот способ входа недоступен",
        "error_provider_identity": "Вход через поставщика идентичности не удался",
        "error_provider_domain": "Эта учётная запись вне разрешённых доменов",
        "error_provider_unverified": "Поставщик идентичности не подтвердил адрес электронной почты",
        "error_provider_unavailable": "Поставщик идентичности недоступен. Попробуйте позже",
        "error_user_denied": "Пользователь не зарегистрирован или заблокирован",
        "error_directory_unavailable": "Каталог пользователей недоступен",
        "error_redirect_host": "Адрес возврата этого приложения не разрешён",
        "consent_title": "Разрешить доступ?",
        "consent_app": "Приложение",
        "consent_redirect": "После входа вы попадёте на",
        "consent_unnamed": "Приложение без названия",
        "consent_warning": (
            "Продолжайте, только если вы сами начали этот вход и узнаёте адрес выше."
        ),
        "or_api_key": "или по ключу API",
        "token_help": "Ключ выдаёт администратор; он показывается один раз при выпуске.",
        "error_hint_generic": "Вернитесь в приложение и начните вход заново.",
        "error_hint_request": (
            "Вернитесь в приложение и начните вход заново. Ссылка действует десять минут."
        ),
        "error_hint_redirect_host": (
            "Адрес возврата приложения не входит в разрешённые; обратитесь к администратору."
        ),
        "error_code_hint": "Если это повторяется, сообщите администратору код:",
        "lang_switcher_label": "Язык",
    },
    "ar": {
        "title": "Keystone MCP — تسجيل الدخول",
        "subtitle": "تسجيل الدخول لربط عميل بمساحة العمل.",
        "email_label": "البريد الإلكتروني",
        "token_label": "رمز API",
        "submit": "تفويض",
        "error_invalid": "رمز API أو البريد الإلكتروني غير صحيح",
        "error_request": "طلب تفويض غير صالح أو منتهي الصلاحية",
        "login_with": "تسجيل الدخول عبر {provider}",
        "error_provider_disabled": "طريقة تسجيل الدخول هذه غير متاحة",
        "error_provider_identity": "فشل تسجيل الدخول عبر مزود الهوية",
        "error_provider_domain": "هذا الحساب خارج النطاقات المسموح بها",
        "error_provider_unverified": "مزود الهوية لم يؤكد عنوان البريد الإلكتروني",
        "error_provider_unavailable": "مزود الهوية غير متاح. حاول مرة أخرى لاحقًا",
        "error_user_denied": "المستخدم غير مسجل أو محظور",
        "error_directory_unavailable": "خدمة المستخدمين غير متاحة",
        "error_redirect_host": "عنوان إعادة التوجيه لهذا التطبيق غير مسموح به",
        "consent_title": "السماح بالوصول؟",
        "consent_app": "التطبيق",
        "consent_redirect": "بعد تسجيل الدخول سيتم تحويلك إلى",
        "consent_unnamed": "تطبيق بدون اسم",
        "consent_warning": "تابع فقط إذا بدأت هذا الاتصال بنفسك وتتعرف على العنوان أعلاه.",
        "or_api_key": "أو بمفتاح API",
        "token_help": "يصدر المسؤول المفتاح؛ يُعرض مرة واحدة فقط عند الإنشاء.",
        "error_hint_generic": "ارجع إلى التطبيق وابدأ تسجيل الدخول من جديد.",
        "error_hint_request": "ارجع إلى التطبيق وابدأ تسجيل الدخول من جديد. الرابط صالح لعشرة دقائق.",
        "error_hint_redirect_host": "عنوان إرجاع التطبيق غير مسموح به؛ تواصل مع المسؤول.",
        "error_code_hint": "إذا تكرر ذلك، أبلغ المسؤول بالرمز:",
        "lang_switcher_label": "اللغة",
    },
}


def _lang_cookie_names(base_url: str) -> tuple[str, ...]:
    if base_url.startswith("https://"):
        return (_LANG_COOKIE_NAME_HOST_PREFIXED, _LANG_COOKIE_NAME)
    return (_LANG_COOKIE_NAME, _LANG_COOKIE_NAME_HOST_PREFIXED)


def _pick_language(
    request: Request, default_lang: str = FALLBACK_LANG, *, base_url: str = ""
) -> str:
    """Select a supported UI language for sign-in pages.

    Priority: explicit ``?lang=``, then the ``km_lang`` choice cookie, then
    ``Accept-Language``, then the deployment's ``KEYSTONE_MCP_LOGIN_DEFAULT_LANG``.
    """
    override = request.query_params.get("lang", "").strip().lower()
    if override in TRANSLATIONS:
        return override

    for cookie_name in _lang_cookie_names(base_url):
        cookie_lang = request.cookies.get(cookie_name, "").strip().lower()
        if cookie_lang in TRANSLATIONS:
            return cookie_lang

    header = request.headers.get("accept-language", "")
    best_lang = default_lang if default_lang in TRANSLATIONS else FALLBACK_LANG
    best_q = -1.0
    for part in header.split(","):
        token = part.strip()
        if not token:
            continue
        chunks = token.split(";")
        primary = chunks[0].strip().lower().split("-")[0]
        quality = 1.0
        for extra in chunks[1:]:
            extra = extra.strip()
            if extra.startswith("q="):
                try:
                    quality = float(extra[2:])
                except ValueError:
                    quality = 0.0
        if primary in TRANSLATIONS and quality > best_q:
            best_q = quality
            best_lang = primary
    return best_lang


def _consent_redirect_location(redirect_uri: str) -> str:
    """The short, bolded redirect target shown on the consent screen.

    For ``http``/``https`` this is the lower-cased host, with the port
    appended only when it is not that scheme's default (so
    ``http://localhost:9999/cb`` shows ``localhost:9999`` but
    ``https://claude.ai/cb`` just shows ``claude.ai``). Any other scheme
    (e.g. a native app's ``cursor://...``) shows ``scheme://host`` instead,
    since there is no notion of a "port" worth hiding there.
    """
    parsed = urlparse(redirect_uri)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    if scheme in ("http", "https"):
        if parsed.port is not None and parsed.port != _DEFAULT_SCHEME_PORTS.get(scheme):
            return f"{host}:{parsed.port}"
        return host
    return f"{scheme}://{host}"


def _field_label(t: dict[str, str], field: FormField) -> str:
    """The (un-escaped) label text for one form field, falling back to its name.

    ``field.label_key`` names a translation key the provider chose; a
    third-party provider's key missing from ``TRANSLATIONS`` must not 500 the
    login page (``t`` is a plain ``dict``, so a bare ``t[field.label_key]``
    raises ``KeyError``) -- it falls back to the field's own (validated,
    startup-checked) name instead. The caller still ``html.escape``s whatever
    this returns.
    """
    return t.get(field.label_key, field.name)


class _PendingAuthorization:
    __slots__ = ("client_id", "params")

    def __init__(self, client_id: str, params: AuthorizationParams) -> None:
        self.client_id = client_id
        self.params = params


class _LoginAttempt:
    """A redirect provider's in-flight sign-in attempt, keyed by ``state``.

    Replaces the Google-only ``_GooglePendingState``: the same record shape
    now serves any ``RedirectLoginProvider`` (X03). ``attempt`` is whatever
    private per-attempt data the provider's own ``begin()`` returned (a
    nonce, a PKCE verifier, ...) — Keystone never looks inside it, only
    stores and hands it back to ``complete()``.
    """

    __slots__ = ("txn_id", "provider", "attempt", "csrf_hash")

    def __init__(self, txn_id: str, provider: str, attempt: dict[str, str], csrf_hash: str) -> None:
        self.txn_id = txn_id
        self.provider = provider
        self.attempt = attempt
        self.csrf_hash = csrf_hash


class KeystoneOAuthProvider(OAuthProvider):
    def __init__(
        self,
        settings: Settings,
        oauth_store: OAuthStore,
        login_pending_store: LoginPendingStore,
        *,
        login_providers: Sequence[LoginProvider],
        user_resolver: UserDirectoryResolver | None = None,
        login_throttle: LoginAttemptThrottle | None = None,
        oauth_endpoint_throttle: LoginAttemptThrottle | None = None,
        login_failure_limiter: LoginFailureLimiter | None = None,
        observability: RbacObservability | None = None,
        identity_binder: IdentityBindingDirectory | None = None,
    ) -> None:
        super().__init__(
            base_url=settings.base_url,
            issuer_url=settings.base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=settings.oauth_dcr_enabled
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=None,
        )
        self._settings = settings
        self._store = oauth_store
        self._pending_store = login_pending_store
        self._providers: dict[str, LoginProvider] = {p.name: p for p in login_providers}
        self._user_resolver = user_resolver
        self._login_throttle = login_throttle or LoginAttemptThrottle(
            settings.login_throttle_ip_max,
            settings.login_throttle_email_max,
            settings.login_throttle_window_seconds,
        )
        self._oauth_endpoint_throttle = oauth_endpoint_throttle or LoginAttemptThrottle(
            ip_max=settings.oauth_throttle_ip_max,
            email_max=0,
            window_seconds=settings.login_throttle_window_seconds,
        )
        if login_failure_limiter is not None:
            self._login_failure_limiter = login_failure_limiter
        else:
            shared_redis = getattr(login_pending_store, "redis", None)
            if shared_redis is not None:
                prefix = normalize_login_key_prefix(settings.login_pending_key_prefix)
                self._login_failure_limiter = RedisLoginFailureLimiter(
                    shared_redis,
                    key_prefix=prefix,
                    max_failures=settings.login_throttle_email_max,
                    window_seconds=settings.login_throttle_window_seconds,
                )
            else:
                self._login_failure_limiter = InMemoryLoginFailureLimiter(self._login_throttle)
        self._observability = observability
        self._identity_binder = identity_binder

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)

        def _rebuild(route: Route, app: object) -> Route:
            return Route(
                path=route.path,
                endpoint=app,
                methods=route.methods,
                name=route.name,
                include_in_schema=route.include_in_schema,
            )

        wrapped: list[Route] = []
        for route in routes:
            if not isinstance(route, Route):
                wrapped.append(route)
                continue
            route_methods = route.methods or frozenset()
            # Use route.app (the ASGI callable Starlette already built from
            # the endpoint, wrapping a plain request handler via
            # request_response when needed) rather than route.endpoint,
            # which for /authorize is a bare ``handle(request)`` method and
            # is not ASGI-callable itself.
            app = route.app
            if route.path == "/authorize":
                app = _AuthorizeRedirectHostGuard(app, self._store, self._settings)
                app = _AuthorizeErrorRedirectGuard(app, self._settings, self)
            if route.path == "/register" and "POST" in route_methods:
                app = _RegisterMetadataGuard(app, self._observability)
            if (
                route.path == "/register"
                and "POST" in route_methods
                and self._login_throttle.enabled()
            ):
                app = wrap_asgi_with_ip_login_throttle(
                    app, self._login_throttle, frozenset({"POST"})
                )
            elif route.path == "/authorize" and self._oauth_endpoint_throttle.enabled():
                app = wrap_asgi_with_ip_login_throttle(
                    app, self._oauth_endpoint_throttle, frozenset({"GET", "POST"})
                )
            elif route.path == "/token" and "POST" in route_methods:
                app = _TokenTemporarilyUnavailableGuard(app)
                if self._oauth_endpoint_throttle.enabled():
                    app = wrap_asgi_with_ip_login_throttle(
                        app, self._oauth_endpoint_throttle, frozenset({"POST"})
                    )
            elif (
                route.path == "/revoke"
                and "POST" in route_methods
                and self._oauth_endpoint_throttle.enabled()
            ):
                app = wrap_asgi_with_ip_login_throttle(
                    app, self._oauth_endpoint_throttle, frozenset({"POST"})
                )
            wrapped.append(_rebuild(route, app) if app is not route.app else route)
        return wrapped

    def _callback_url(self, name: str) -> str:
        """Where a redirect provider named *name* sends the browser back.

        For the provider named ``google`` this always equals
        ``settings.google_redirect_uri`` (the address registered with Google
        — S4), since that property uses this same ``{base_url}/login/{name}/
        callback`` formula.
        """
        return f"{self._settings.base_url.rstrip('/')}/login/{name}/callback"

    def _form_provider(self) -> FormLoginProvider | None:
        """The configured ``form``-kind provider, if any (at most one — validated at startup)."""
        for provider in self._providers.values():
            if provider.kind == "form":
                return provider  # type: ignore[return-value]
        return None

    @staticmethod
    def _verify_identity_route(identity: LoginIdentity, route_name: str) -> LoginIdentity | None:
        """Confirm ``identity.provider`` matches the route it came back on, and normalize its email.

        ``identity.provider`` becomes the issued token's ``auth_method``
        claim. Without this check, a third-party provider configured under
        some other name could simply report ``provider="google"`` in the
        ``LoginIdentity`` it returns and claim to be the built-in Google
        provider -- Keystone must instead derive ``auth_method`` from *which
        route the sign-in came back on* (``name`` in
        ``handle_login_callback``, ``form_provider.name`` in
        ``handle_login``), and refuse the attempt outright when a provider's
        own claim disagrees with it. RBAC's interactive-human gate
        (``rbac/human_identity.py``) no longer trusts ``auth_method ==
        "google"`` either (X05): it reads the ``interactive`` claim, which
        ``_complete_login`` derives from the *registered provider's own*
        ``LoginProvider.interactive`` -- looked up by this same route name,
        not from the identity a provider hands back -- so a provider cannot
        earn that trust by self-reporting it any more than it can the name.

        The email is normalized again here (on top of the generic providers'
        own normalization) as defence in depth: a provider is third-party
        code, and the users-directory lookup and the token's ``subject`` must
        not depend on it having normalized correctly.

        Returns ``None`` (logging a warning naming both provider names, but
        never the email) when the names disagree.
        """
        if identity.provider != route_name:
            logger.warning(
                "login provider %s reported provider=%r; refusing the sign-in",
                route_name,
                identity.provider,
            )
            return None
        if email_folds_to_ascii(identity.email):
            logger.warning(
                "login identity email contains characters that fold to ASCII; refusing the sign-in"
            )
            return None
        normalized = replace(identity, email=normalize_email(identity.email))
        if subject_type_of(normalized.email) == "service":
            logger.warning(
                "login provider %s returned a service-account subject; refusing the sign-in",
                route_name,
            )
            return None
        return normalized

    def _csrf_cookie_name(self) -> str:
        """The ``km_login_csrf`` cookie's name for this deployment (finding #4).

        ``__Host-`` only over ``https``: the prefix requires ``Secure``, and
        claiming it on a plain-``http`` deployment (local/demo) would be
        dishonest about a guarantee the browser is not actually enforcing.
        """
        if self._settings.base_url.startswith("https://"):
            return _CSRF_COOKIE_NAME_HOST_PREFIXED
        return _CSRF_COOKIE_NAME

    def _csrf_cookie_path(self) -> str:
        """``Path=/`` is one of the ``__Host-`` prefix's own requirements."""
        if self._settings.base_url.startswith("https://"):
            return "/"
        return "/login"

    def _lang_cookie_name(self) -> str:
        if self._settings.base_url.startswith("https://"):
            return _LANG_COOKIE_NAME_HOST_PREFIXED
        return _LANG_COOKIE_NAME

    def _maybe_set_lang_cookie(self, response: Response, request: Request, lang: str) -> None:
        explicit = request.query_params.get("lang", "").strip().lower()
        if explicit not in TRANSLATIONS:
            return
        response.set_cookie(
            self._lang_cookie_name(),
            lang,
            max_age=_LANG_COOKIE_MAX_AGE_SECONDS,
            path=self._csrf_cookie_path(),
            httponly=True,
            samesite="lax",
            secure=self._settings.base_url.startswith("https://"),
        )

    def _txn_query(self, txn_id: str) -> str:
        if not txn_id:
            return ""
        return f"txn={quote(txn_id)}&"

    def _translation(self, lang: str) -> dict[str, str]:
        return TRANSLATIONS.get(lang, TRANSLATIONS[FALLBACK_LANG])

    def _build_provider_views(self, t: dict[str, str]) -> list[ProviderView]:
        views: list[ProviderView] = []
        for provider in self._providers.values():
            if provider.kind == "redirect":
                views.append(ProviderView(provider.name, provider.kind, provider.title, ()))
                continue
            if provider.kind != "form":
                continue
            fields: list[FieldView] = []
            for field in provider.form_fields():
                help_key: str | None = None
                autocomplete = "off"
                inputmode: str | None = None
                if field.name == "email":
                    autocomplete = "email"
                    inputmode = "email"
                elif field.name == "api_token":
                    help_key = "token_help"
                fields.append(
                    FieldView(
                        field.name,
                        field.input_type,
                        _field_label(t, field),
                        help_key,
                        autocomplete,
                        inputmode,
                    )
                )
            views.append(ProviderView(provider.name, provider.kind, provider.title, tuple(fields)))
        return views

    def _error_page(
        self, lang: str, error_key: str, *, txn_query: str = "", status_code: int = 400
    ) -> str:
        return render_error_page(
            lang=lang,
            t=self._translation(lang),
            brand=self._settings.login_brand,
            error_key=error_key,
            status_code=status_code,
            txn_query=txn_query,
        )

    def _html_error(
        self,
        request: Request | None,
        lang: str,
        error_key: str,
        status_code: int,
    ) -> Response:
        txn_query = ""
        if request is not None:
            txn_query = self._txn_query(request.query_params.get("txn", ""))
        content = self._error_page(error_key=error_key, lang=lang, txn_query=txn_query)
        response = _html_response(content, status_code=status_code)
        if request is not None:
            self._maybe_set_lang_cookie(response, request, lang)
        return response

    # ── Client management (DCR, RFC 7591) ─────────────────────────────────
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self._store.get_client(client_id)

    def _refuse_if_client_redirect_uris_not_allowed(
        self, client: OAuthClientInformationFull
    ) -> None:
        """Refuse a token exchange for a client the redirect-host allowlist no longer permits.

        ``register_client`` and ``authorize`` both check the allowlist, but
        neither retroactively evicts a client that was registered before the
        allowlist existed, or before it was tightened. Without this check such
        a client can keep renewing its access and refresh tokens forever
        (``touch_client`` plus rotation) even though it could never register
        or start a fresh ``/authorize`` today (A17, finding #3). Raising
        ``TokenError`` here is safe for both callers: ``/token`` is a JSON API
        with no redirect to protect against, unlike ``/authorize``.
        """
        allowed_hosts = self._settings.oauth_allowed_redirect_hosts
        allowed_scheme_hosts = self._settings.oauth_allowed_redirect_scheme_hosts
        if _client_redirect_uris_allowed(client, allowed_hosts, allowed_scheme_hosts):
            return
        logger.warning(
            "token exchange refused: client %s has a redirect_uri host that is not allowed",
            client.client_id,
        )
        raise TokenError(
            error="unauthorized_client",
            error_description="redirect_uri host is not allowed",
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if (
            client_info.client_name is not None
            and len(client_info.client_name) > _CLIENT_NAME_MAX_CHARS
        ):
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="client_name is too long",
            )
        redirect_uris = client_info.redirect_uris or []
        if len(redirect_uris) > _REDIRECT_URIS_MAX:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="too many redirect_uris",
            )

        allowed_hosts = self._settings.oauth_allowed_redirect_hosts
        allowed_scheme_hosts = self._settings.oauth_allowed_redirect_scheme_hosts
        if allowed_hosts or allowed_scheme_hosts:
            if not client_info.redirect_uris:
                # `redirect_uris: null` validates against the SDK's own model
                # (it is `list[AnyUrl] | None`), but it cannot be shown to be
                # on an allowed host when there is nothing to check (finding
                # #5) — refuse instead of iterating over `None`.
                logger.warning(
                    "client registration refused: redirect_uris is empty but a "
                    "redirect host allowlist is configured"
                )
                if self._observability is not None:
                    self._observability.record_oauth_client_registration(
                        outcome="rejected_redirect_host"
                    )
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=(
                        "redirect_uris is required when a redirect host allowlist is configured"
                    ),
                )
            for redirect_uri in client_info.redirect_uris:
                if not _redirect_uri_allowed(
                    str(redirect_uri), allowed_hosts, allowed_scheme_hosts
                ):
                    host = urlparse(str(redirect_uri)).hostname
                    logger.warning(
                        "client registration refused: redirect_uri host not allowed: %s",
                        host,
                    )
                    if self._observability is not None:
                        self._observability.record_oauth_client_registration(
                            outcome="rejected_redirect_host"
                        )
                    raise RegistrationError(
                        error="invalid_redirect_uri",
                        error_description=f"redirect_uri host is not allowed: {host}",
                    )

        max_clients = self._settings.oauth_max_clients
        if max_clients > 0:
            current_count = await self._store.count_clients()
            if current_count >= max_clients:
                evicted = await self._store.evict_unused_client()
                if evicted is not None:
                    logger.info(
                        "client registration: evicted unused client %s to stay under the limit",
                        evicted,
                    )
                    if self._observability is not None:
                        self._observability.record_oauth_client_eviction()
                else:
                    logger.warning(
                        "client registration refused: limit %d reached (%d registered)",
                        max_clients,
                        current_count,
                    )
                    if self._observability is not None:
                        self._observability.record_oauth_client_registration(
                            outcome="rejected_limit", client_count=current_count
                        )
                    raise RegistrationError(
                        error="invalid_client_metadata",
                        error_description="client registration limit reached",
                    )

        await self._store.put_client(client_info)
        if self._observability is not None:
            client_count = await self._store.count_clients()
            self._observability.record_oauth_client_registration(
                outcome="created", client_count=client_count
            )

    # ── Authorization (delegates credential entry to the login page) ──────
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Stash the request and redirect the browser to our login page.

        No authorization code is issued here: the code is only minted after the
        api_token is validated on the login POST.
        """
        allowed_hosts = self._settings.oauth_allowed_redirect_hosts
        allowed_scheme_hosts = self._settings.oauth_allowed_redirect_scheme_hosts
        if (allowed_hosts or allowed_scheme_hosts) and not _redirect_uri_allowed(
            str(params.redirect_uri), allowed_hosts, allowed_scheme_hosts
        ):
            # The SDK already matched params.redirect_uri against the client's
            # registered redirect_uris, so this only fires for a client that
            # registered before the restriction was turned on (A17). No
            # transaction is created.
            #
            # This deliberately does not raise AuthorizeError: the SDK's
            # authorization handler already resolved `client` and
            # `redirect_uri` by the time this method runs, so an AuthorizeError
            # here is caught by a handler that redirects it straight to that
            # same (disallowed) redirect_uri with `error`/`state` query
            # parameters — exactly the host this check exists to keep the
            # browser away from. Returning our own error page's URL instead
            # keeps the browser on this host; the SDK 302s to whatever URL
            # `authorize()` returns, so this is still a redirect, just not to
            # the attacker's address.
            logger.warning(
                "authorize refused: redirect_uri host not allowed: %s",
                urlparse(str(params.redirect_uri)).hostname,
            )
            return f"{self._settings.base_url.rstrip('/')}/login/redirect-not-allowed"

        txn_id = secrets.token_urlsafe(24)
        pending = _PendingAuthorization(client.client_id, params)
        await self._put_pending_txn(txn_id, pending)
        return f"{self._settings.base_url.rstrip('/')}/login?{urlencode({'txn': txn_id})}"

    async def _put_pending_txn(self, txn_id: str, pending: _PendingAuthorization) -> None:
        payload = pending.params.model_dump_json()
        envelope = f"{pending.client_id}\n{payload}"
        await self._pending_store.put(
            _NS_PENDING_TXN,
            txn_id,
            envelope,
            self._settings.login_pending_txn_ttl_seconds,
        )

    async def _get_pending_txn(self, txn_id: str) -> _PendingAuthorization | None:
        raw = await self._pending_store.get(_NS_PENDING_TXN, txn_id)
        if raw is None:
            return None
        return _parse_pending_txn_raw(raw)

    async def _consume_pending_txn(self, txn_id: str) -> _PendingAuthorization | None:
        raw = await self._pending_store.consume(_NS_PENDING_TXN, txn_id)
        if raw is None:
            return None
        return _parse_pending_txn_raw(raw)

    async def _put_auth_code(
        self,
        code: AuthorizationCode,
        *,
        auth_method: str,
        interactive: bool,
        auth_time: int | None = None,
        key_id: str | None = None,
        key_id_known: bool = False,
        key_expires_at: int | None = None,
    ) -> None:
        ttl = max(int(code.expires_at - time.time()), 1)
        await self._pending_store.put(
            _NS_AUTH_CODE,
            code.code,
            _encode_auth_code_envelope(
                code,
                auth_method,
                interactive,
                auth_time=auth_time,
                key_id=key_id,
                key_id_known=key_id_known,
                key_expires_at=key_expires_at,
            ),
            ttl,
        )

    async def _get_auth_code(self, code_str: str) -> AuthorizationCode | None:
        raw = await self._pending_store.get(_NS_AUTH_CODE, code_str)
        if raw is None:
            return None
        envelope = _parse_auth_code_envelope(raw)
        if envelope is None:
            return None
        code = envelope.code
        if code.expires_at < time.time():
            await self._pending_store.consume(_NS_AUTH_CODE, code_str)
            return None
        return code

    async def _consume_auth_code(self, code_str: str) -> _AuthCodeEnvelope | None:
        raw = await self._pending_store.consume(_NS_AUTH_CODE, code_str)
        if raw is None:
            return None
        return _parse_auth_code_envelope(raw)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = await self._get_auth_code(authorization_code)
        if code is None:
            digest = token_digest(authorization_code)
            used = await self._pending_store.get(_NS_CODE_USED, digest)
            if used is not None:
                try:
                    data = json.loads(used)
                except json.JSONDecodeError:
                    data = {}
                if data.get("client_id") == client.client_id:
                    await self._on_code_replay(
                        client,
                        subject=str(data.get("subject") or ""),
                        client_id=client.client_id,
                    )
            return None
        if code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._refuse_if_client_redirect_uris_not_allowed(client)

        # Single-use code (atomic consume).
        envelope = await self._consume_auth_code(authorization_code.code)
        if envelope is None:
            await self._on_code_replay(
                client,
                subject=authorization_code.subject or "",
                client_id=client.client_id,
            )
            raise TokenError(
                error="invalid_grant",
                error_description="authorization code invalid or already used",
            )
        consumed_code = envelope.code
        if consumed_code.code != authorization_code.code:
            await self._on_code_replay(
                client,
                subject=authorization_code.subject or "",
                client_id=client.client_id,
            )
            raise TokenError(
                error="invalid_grant",
                error_description="authorization code invalid or already used",
            )

        auth_method = envelope.auth_method
        interactive = envelope.interactive
        email = authorization_code.subject or ""
        access_token = f"km_at_{secrets.token_urlsafe(32)}"
        refresh_token = f"km_rt_{secrets.token_urlsafe(32)}"
        now = int(time.time())
        expires_at = now + self._settings.token_cache_ttl_seconds
        code_iat = int(consumed_code.expires_at) - self._settings.auth_code_ttl_seconds
        token_claims = _human_access_claims(
            email,
            auth_method,
            interactive,
            now,
            envelope.key_id if envelope.key_id_known else None,
        )
        session_meta = _meta_from_envelope(envelope, authorization_code.resource)
        encoded_meta = encode_refresh_meta(session_meta)

        # Renew the client's lifetime before writing the refresh token it will
        # own, so the client record never expires ahead of a token issued
        # under it.
        await self._store.touch_client(client.client_id)
        access_record = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            resource=authorization_code.resource,
            subject=email,
            claims=token_claims,
        )
        refresh_record = KeystoneRefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + self._settings.refresh_token_ttl_seconds,
            subject=email,
            iat=now,
        )
        refresh_meta_arg = encoded_meta if self._store.writes_refresh_meta else None
        try:
            await self._store.commit_token_pair(
                subject=email,
                consumed_iat=code_iat,
                access=access_record,
                refresh=refresh_record,
                refresh_meta=refresh_meta_arg,
            )
        except CredentialRevokedError:
            if self._observability is not None:
                self._observability.record_token_exchange(
                    grant_type="authorization_code", outcome="revoked"
                )
            raise TokenError(
                error="invalid_grant",
                error_description="session was revoked",
            ) from None
        if not self._store.writes_refresh_meta:
            await self._put_refresh_meta(refresh_token, session_meta)
        used_payload = json.dumps(
            {"subject": email, "client_id": client.client_id},
            separators=(",", ":"),
        )
        await self._pending_store.put(
            _NS_CODE_USED,
            token_digest(authorization_code.code),
            used_payload,
            self._settings.auth_code_ttl_seconds,
        )
        if self._observability is not None:
            self._observability.record_token_exchange(
                grant_type="authorization_code", outcome="issued"
            )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self._settings.token_cache_ttl_seconds,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
            refresh_token=refresh_token,
        )

    # ── Refresh tokens ────────────────────────────────────────────────────
    async def _refuse_refresh(
        self,
        reason: str,
        *,
        refresh_token: RefreshToken,
        email: str,
        client: OAuthClientInformationFull,
        revoke_all_sessions: bool = False,
    ) -> None:
        descriptions = {
            "session_expired": "session reached its maximum age; sign in again",
            "key_revoked": "the API key this session was opened with is no longer valid",
            "key_expired": "the API key this session was opened with is no longer valid",
            "user_denied": "user is not allowed to sign in",
        }
        await self._store.delete_refresh_token(refresh_token.token)
        await self._pending_store.consume(_NS_REFRESH_AUTH, refresh_token.token)
        if revoke_all_sessions and email:
            from keystone_mcp.auth.sessions import SessionRevoker

            revoker = SessionRevoker(self._store, self._pending_store)
            await revoker.revoke_subject(email)
        if self._observability is not None:
            self._observability.record_token_exchange(grant_type="refresh_token", outcome=reason)
            self._observability.record_session_event(
                action="refresh_refused",
                subject=email,
                client_id=client.client_id,
                reason=reason,
            )
        raise TokenError(
            error="invalid_grant",
            error_description=descriptions.get(reason, reason),
        )

    async def _refresh_recheck_session(
        self,
        *,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        old_meta: RefreshMeta,
        email: str,
    ) -> tuple[int, int, RefreshMeta]:
        global _REFRESH_NO_RESOLVER_WARNED  # noqa: PLW0603

        now = int(time.time())
        auth_time = old_meta.auth_time
        if auth_time is None:
            auth_time = now
        working_meta = _meta_carry_forward(
            old_meta, resource=old_meta.resource, auth_time=auth_time
        )

        max_age = self._settings.session_max_age_seconds
        if max_age > 0 and now - auth_time >= max_age:
            await self._refuse_refresh(
                "session_expired",
                refresh_token=refresh_token,
                email=email,
                client=client,
            )

        key_expires_at = old_meta.key_expires_at if old_meta.key_id_known else None
        if old_meta.key_id_known and isinstance(old_meta.key_id, str):
            if key_expires_at is not None and key_expires_at <= now:
                await self._refuse_refresh(
                    "key_expired",
                    refresh_token=refresh_token,
                    email=email,
                    client=client,
                )
            resolver = self._user_resolver
            if resolver is None:
                await self._refuse_refresh(
                    "key_revoked",
                    refresh_token=refresh_token,
                    email=email,
                    client=client,
                )
            state = "unknown"
            if isinstance(resolver, ApiKeyStateReader):
                try:
                    state = await resolver.api_key_state(old_meta.key_id, subject=email)
                except UserDirectoryUnavailableError as exc:
                    if self._observability is not None:
                        self._observability.record_token_exchange(
                            grant_type="refresh_token", outcome="directory_unavailable"
                        )
                    raise RefreshTemporarilyUnavailableError from exc
            if state == "active":
                pass
            elif state == "revoked":
                await self._refuse_refresh(
                    "key_revoked",
                    refresh_token=refresh_token,
                    email=email,
                    client=client,
                )
            elif state == "expired":
                await self._refuse_refresh(
                    "key_expired",
                    refresh_token=refresh_token,
                    email=email,
                    client=client,
                )
            else:
                await self._refuse_refresh(
                    "key_revoked",
                    refresh_token=refresh_token,
                    email=email,
                    client=client,
                )

        resolver = self._user_resolver
        if resolver is not None:
            try:
                resolved = await resolver.resolve(email, critical=True)
            except UserDirectoryUnavailableError as exc:
                if self._observability is not None:
                    self._observability.record_token_exchange(
                        grant_type="refresh_token", outcome="directory_unavailable"
                    )
                raise RefreshTemporarilyUnavailableError from exc
            if not resolved.exists or resolved.is_blocked or resolved.subject_type == "service":
                await self._refuse_refresh(
                    "user_denied",
                    refresh_token=refresh_token,
                    email=email,
                    client=client,
                    revoke_all_sessions=True,
                )
        elif not _REFRESH_NO_RESOLVER_WARNED:
            logger.warning(
                "refresh does not re-check the users directory: no directory resolver is configured"
            )
            _REFRESH_NO_RESOLVER_WARNED = True

        refresh_expires_at = now + self._settings.refresh_token_ttl_seconds
        if max_age > 0:
            refresh_expires_at = min(refresh_expires_at, auth_time + max_age)
        if key_expires_at is not None:
            refresh_expires_at = min(refresh_expires_at, key_expires_at)
        access_expires_at = min(now + self._settings.token_cache_ttl_seconds, refresh_expires_at)
        return now, access_expires_at, working_meta

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token = await self._store.get_refresh_token(refresh_token)
        if token is not None:
            if token.client_id != client.client_id:
                return None
            if token.expires_at is not None and token.expires_at < time.time():
                await self._store.delete_refresh_token(refresh_token)
                return None
            return token
        rotated = await self._store.get_rotated_refresh(refresh_token)
        if rotated is None or rotated.client_id != client.client_id:
            return None
        return KeystoneRefreshToken(
            token=refresh_token,
            client_id=rotated.client_id,
            scopes=rotated.scopes,
            expires_at=rotated.expires_at,
            resource=rotated.resource,
            subject=rotated.subject,
            rotated=True,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate the refresh token atomically; replays within the grace window reuse the response."""
        self._refuse_if_client_redirect_uris_not_allowed(client)
        if isinstance(refresh_token, KeystoneRefreshToken) and refresh_token.rotated:
            return await self._replay_or_grace(client, refresh_token)

        old_meta = await self._read_refresh_meta(refresh_token.token)
        if old_meta is None:
            logger.warning("refresh refused: session marker is missing")
            await self._store.delete_refresh_token(refresh_token.token)
            if self._observability is not None:
                self._observability.record_token_exchange(
                    grant_type="refresh_token", outcome="marker_missing"
                )
            raise TokenError(
                error="invalid_grant",
                error_description="session marker is missing; sign in again",
            )
        auth_method = old_meta.auth_method
        resource = old_meta.resource
        interactive = old_meta.interactive
        if auth_method not in self._providers:
            logger.warning(
                "refresh refused: sign-in provider %r is no longer configured", auth_method
            )
            await self._store.delete_refresh_token(refresh_token.token)
            await self._pending_store.consume(_NS_REFRESH_AUTH, refresh_token.token)
            if self._observability is not None:
                self._observability.record_token_exchange(
                    grant_type="refresh_token", outcome="provider_removed"
                )
            raise TokenError(
                error="invalid_grant",
                error_description="sign-in provider is no longer configured",
            )
        email = refresh_token.subject or ""
        granted = scopes or refresh_token.scopes
        now, access_expires_at, new_meta = await self._refresh_recheck_session(
            client=client,
            refresh_token=refresh_token,
            old_meta=old_meta,
            email=email,
        )
        refresh_expires_at = now + self._settings.refresh_token_ttl_seconds
        max_age = self._settings.session_max_age_seconds
        auth_time = new_meta.auth_time or now
        if max_age > 0:
            refresh_expires_at = min(refresh_expires_at, auth_time + max_age)
        key_expires_at = old_meta.key_expires_at if old_meta.key_id_known else None
        if key_expires_at is not None:
            refresh_expires_at = min(refresh_expires_at, key_expires_at)
        expires_in = max(1, access_expires_at - now)
        access_token = f"km_at_{secrets.token_urlsafe(32)}"
        new_refresh = f"km_rt_{secrets.token_urlsafe(32)}"
        token_claims = _human_access_claims(
            email,
            auth_method,
            interactive,
            now,
            old_meta.key_id if old_meta.key_id_known else None,
        )
        new_meta = _meta_carry_forward(new_meta, resource=resource, auth_time=auth_time)
        encoded_meta = encode_refresh_meta(new_meta)
        response = OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=" ".join(granted) if granted else None,
            refresh_token=new_refresh,
        )

        grace_seconds = self._settings.oauth_refresh_grace_seconds
        grace_blob: str | None = None
        if grace_seconds > 0:
            grace_blob = _seal_grace(refresh_token.token, response)

        if refresh_token.expires_at is None:
            used_ttl = self._settings.refresh_token_ttl_seconds
        else:
            used_ttl = max(int(refresh_token.expires_at - now), 1)
        used_json = json.dumps(
            {
                "subject": email,
                "client_id": client.client_id,
                "scopes": granted,
                "expires_at": refresh_token.expires_at,
                "resource": resource,
                "rotated_at": now,
            },
            separators=(",", ":"),
        )
        old_meta_ttl = max(grace_seconds, 1)
        rotation = RotationRecord(
            used_json=used_json,
            used_ttl=used_ttl,
            grace_blob=grace_blob,
            grace_ttl=grace_seconds,
            old_meta=encode_refresh_meta(old_meta) if self._store.writes_refresh_meta else None,
            old_meta_ttl=old_meta_ttl,
        )

        await self._store.touch_client(client.client_id)
        access_record = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=granted,
            expires_at=access_expires_at,
            resource=resource,
            subject=email,
            claims=token_claims,
        )
        refresh_record = KeystoneRefreshToken(
            token=new_refresh,
            client_id=client.client_id,
            scopes=granted,
            expires_at=refresh_expires_at,
            subject=email,
            iat=now,
        )
        consumed_iat = self._store.refresh_credential_iat(refresh_token)
        refresh_meta_arg = encoded_meta if self._store.writes_refresh_meta else None
        try:
            await self._store.commit_token_pair(
                subject=email,
                consumed_iat=consumed_iat,
                access=access_record,
                refresh=refresh_record,
                replace_refresh_token=refresh_token.token,
                refresh_meta=refresh_meta_arg,
                rotation=rotation,
            )
        except RefreshTokenAlreadyRotatedError:
            replay_token = KeystoneRefreshToken(
                token=refresh_token.token,
                client_id=refresh_token.client_id,
                scopes=refresh_token.scopes,
                expires_at=refresh_token.expires_at,
                subject=email,
                rotated=True,
            )
            return await self._replay_or_grace(client, replay_token)
        except CredentialRevokedError:
            await self._pending_store.consume(_NS_REFRESH_AUTH, refresh_token.token)
            if self._observability is not None:
                self._observability.record_token_exchange(
                    grant_type="refresh_token", outcome="revoked"
                )
            raise TokenError(
                error="invalid_grant",
                error_description="session was revoked",
            ) from None
        if not self._store.writes_refresh_meta:
            await self._put_refresh_meta(new_refresh, new_meta)
            await self._put_refresh_meta(refresh_token.token, old_meta, ttl_seconds=old_meta_ttl)
        if self._observability is not None:
            self._observability.record_token_exchange(grant_type="refresh_token", outcome="issued")
        return response

    async def _replay_or_grace(
        self, client: OAuthClientInformationFull, refresh_token: KeystoneRefreshToken
    ) -> OAuthToken:
        token_str = refresh_token.token
        blob = await self._store.get_refresh_grace(token_str)
        if blob is not None:
            opened = _open_grace(token_str, blob)
            if opened is not None and opened.refresh_token is not None:
                still_live = await self._store.get_refresh_token(opened.refresh_token)
                if still_live is not None:
                    rotated = await self._store.get_rotated_refresh(token_str)
                    delay_ms: int | None = None
                    if rotated is not None:
                        delay_ms = max(0, int((time.time() - rotated.rotated_at) * 1000))
                    if self._observability is not None:
                        self._observability.record_session_event(
                            action="grace_reissue",
                            subject=refresh_token.subject or "",
                            client_id=client.client_id,
                            delay_ms=delay_ms,
                        )
                        self._observability.record_token_exchange(
                            grant_type="refresh_token", outcome="grace_reissue"
                        )
                    return opened
        rotated = await self._store.get_rotated_refresh(token_str)
        if rotated is not None:
            revoked_count = await self._revoke_client_grant(rotated.subject, client.client_id)
            if self._observability is not None:
                self._observability.record_session_event(
                    action="refresh_replay",
                    subject=rotated.subject,
                    client_id=client.client_id,
                    revoked_tokens=revoked_count,
                )
                self._observability.record_token_exchange(
                    grant_type="refresh_token", outcome="replay_revoked"
                )
            raise TokenError(
                error="invalid_grant",
                error_description="refresh token was already used",
            )
        if self._observability is not None:
            self._observability.record_token_exchange(
                grant_type="refresh_token", outcome="rotated_elsewhere"
            )
        raise TokenError(
            error="invalid_grant",
            error_description="refresh token is no longer valid",
        )

    async def _revoke_client_grant(self, subject: str, client_id: str) -> int:
        access_list, refresh_list = await self._store.subject_tokens(subject)
        access_tokens = [a.token for a in access_list if a.client_id == client_id]
        refresh_tokens = [r.token for r in refresh_list if r.client_id == client_id]
        revoked = await self._store.revoke_tokens(
            subject, access=access_tokens, refresh=refresh_tokens
        )
        for rt in revoked.refresh_tokens:
            await self._pending_store.consume(_NS_REFRESH_AUTH, rt)
        return revoked.access + len(revoked.refresh_tokens)

    async def _on_code_replay(
        self,
        client: OAuthClientInformationFull,
        *,
        subject: str,
        client_id: str,
    ) -> None:
        """Revoke tokens issued for a reused authorization code.

        If two clients exchange the same code concurrently, the loser's replay
        handler may run before the winner's token pair is committed, so the
        winner's tokens can survive that race; a later replay still revokes all
        tokens for that person at that OAuth client.
        """
        if subject:
            revoked_count = await self._revoke_client_grant(subject, client_id)
        else:
            revoked_count = 0
        if self._observability is not None:
            self._observability.record_session_event(
                action="code_replay",
                subject=subject,
                client_id=client_id,
                revoked_tokens=revoked_count or None,
            )
            self._observability.record_token_exchange(
                grant_type="authorization_code", outcome="code_replay"
            )

    # ── Access tokens (Resource Server) ───────────────────────────────────
    async def load_access_token(self, token: str) -> AccessToken | None:
        if token.startswith("ksk_"):
            return await self._verify_service_api_key(token)
        return await self._store.get_access_token(token)

    async def verify_token(self, token: str) -> AccessToken | None:
        from keystone_mcp.observability.tracing import traced

        with traced("keystone.token.verify"):
            if token.startswith("ksk_"):
                access = await self._verify_service_api_key(token)
            else:
                access = await self.load_access_token(token)
            if access is None:
                self._set_token_verify_span(found=False, auth_method=None)
                return None
            # Resource Indicators (RFC 8707): reject a token minted for another
            # audience.
            if access.resource is None:
                if self._settings.require_resource_indicator:
                    logger.info(
                        "rejected access token with no bound resource "
                        "(KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR is on)"
                    )
                    self._set_token_verify_span(
                        found=True,
                        auth_method=(access.claims or {}).get("auth_method"),
                    )
                    return None
                self._set_token_verify_span(
                    found=True,
                    auth_method=(access.claims or {}).get("auth_method"),
                )
                return access
            if not resources_equivalent(access.resource, self._settings.resource_url):
                self._set_token_verify_span(
                    found=True,
                    auth_method=(access.claims or {}).get("auth_method"),
                )
                return None
            self._set_token_verify_span(
                found=True,
                auth_method=(access.claims or {}).get("auth_method"),
            )
            return access

    @staticmethod
    def _set_token_verify_span(*, found: bool, auth_method: str | None) -> None:
        from opentelemetry import trace

        from keystone_mcp.observability.tracing import is_tracing_active

        if not is_tracing_active():
            return
        span = trace.get_current_span()
        if not span.is_recording():
            return
        span.set_attribute("keystone.token.found", found)
        if found and auth_method is not None:
            span.set_attribute("keystone.auth_method", auth_method)

    async def _verify_service_api_key(self, token: str) -> AccessToken | None:
        if self._user_resolver is None:
            return None
        try:
            verification = await self._user_resolver.verify_api_key(token)
        except UserDirectoryUnavailableError:
            logger.warning("users directory unavailable while verifying service API key")
            return None
        if verification is None:
            return None
        if verification.subject_type == "human":
            logger.info(
                "refused bearer API key %s: keys of people work only on the sign-in page",
                verification.key_id,
            )
            return None
        try:
            resolved = await self._user_resolver.resolve(verification.subject)
        except UserDirectoryUnavailableError:
            logger.warning("users directory unavailable while resolving service API key subject")
            return None
        if not resolved.exists or resolved.is_blocked:
            return None
        expires_at = (
            int(verification.expires_at.timestamp())
            if verification.expires_at is not None
            else None
        )
        return AccessToken(
            token=token,
            client_id="keystone-service-key",
            scopes=[],
            expires_at=expires_at,
            resource=self._settings.resource_url,
            subject=verification.subject,
            claims={
                "subject": verification.subject,
                "subject_type": "service",
                "interactive": False,
                "auth_method": "service_key",
                "key_id": verification.key_id,
            },
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            await self._store.delete_access_token(token.token)
            return
        subject = token.subject or ""
        if subject:
            await self._store.revoke_refresh_grant(subject, token.client_id, token.token)
        else:
            await self._store.delete_refresh_token(token.token)
        await self._pending_store.consume(_NS_REFRESH_AUTH, token.token)

    # ── Login page (custom routes, registered by the server) ──────────────
    async def render_login(self, request: Request) -> Response:
        """Render the consent screen (A13): always a page, never a Google redirect.

        Showing the application name and the redirect destination up front, and
        requiring an explicit click on this page before any federated login
        starts, is what closes the "send a victim the /authorize link, they are
        already signed in to Google, the code goes to the attacker's
        redirect_uri" attack: see docs/security-model.md#consent-screen.
        """
        lang = _pick_language(
            request, self._settings.login_default_lang, base_url=self._settings.base_url
        )
        txn_id = request.query_params.get("txn", "")
        pending = await self._get_pending_txn(txn_id)
        if pending is None:
            return self._html_error(request, lang, "error_request", 400)
        client = await self._store.get_client(pending.client_id)
        if client is None:
            return self._html_error(request, lang, "error_request", 400)
        return self._render_consent_page(request, txn_id, lang, pending, client)

    async def render_redirect_not_allowed(self, request: Request) -> Response:
        """``GET /login/redirect-not-allowed``: where ``authorize()`` sends a refused request.

        Reached only when ``KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`` is
        configured and a pre-existing client's redirect_uri is not on it
        (A17, finding #3). No ``txn`` is needed here: by construction nothing
        was ever stashed in the pending store for this request, so there is
        nothing to look up or consume.
        """
        lang = _pick_language(
            request, self._settings.login_default_lang, base_url=self._settings.base_url
        )
        return self._html_error(request, lang, "error_redirect_host", 400)

    async def handle_login(self, request: Request) -> Response:
        """``POST /login``: the single configured ``form``-kind provider's credential form."""
        lang = _pick_language(
            request, self._settings.login_default_lang, base_url=self._settings.base_url
        )
        form_provider = self._form_provider()
        if form_provider is None:
            return self._html_error(request, lang, "error_request", 400)

        allowed_ip, retry_ip = await self._login_throttle.acheck_ip(peer_host(request))
        if not allowed_ip:
            return login_throttle_response(retry_ip)

        form = await request.form()
        txn_id = str(form.get("txn", ""))
        # The login-throttle-by-email key: read directly off the form rather
        # than from the provider's (not-yet-verified) result, exactly as the
        # api_token form has always done, so a bad guess against a given
        # email is throttled before the provider ever runs.
        email = normalize_email(str(form.get("email", "")))

        client_ip = peer_host(request)
        allowed_email, retry_email = await self._login_failure_limiter.check(email, client_ip)
        if not allowed_email:
            return login_throttle_response(retry_email)

        # The consent screen's email+token form posts straight back here with
        # no CSRF check: a third party cannot submit it without the victim's
        # own api_token, so there is nothing for a forged cross-site POST to
        # gain.
        pending = await self._get_pending_txn(txn_id)
        if pending is None:
            return self._html_error(request, lang, "error_request", 400)

        raw_form = {
            field.name: str(form.get(field.name, "")) for field in form_provider.form_fields()
        }
        try:
            identity = await form_provider.verify(raw_form)
        except LoginRejected as exc:
            if exc.reason == "provider_unavailable":
                client = await self._store.get_client(pending.client_id)
                if client is None:
                    return self._html_error(request, lang, "error_request", 400)
                return self._render_consent_page(
                    request,
                    txn_id,
                    lang,
                    pending,
                    client,
                    error_key="error_directory_unavailable",
                    status_code=503,
                )
            logger.info("login rejected by provider %s: %s", form_provider.name, exc.reason)
            await self._login_failure_limiter.record_failure(email, client_ip)
            client = await self._store.get_client(pending.client_id)
            if client is None:
                return self._html_error(request, lang, "error_request", 400)
            return self._render_consent_page(
                request,
                txn_id,
                lang,
                pending,
                client,
                error_key="error_invalid",
                status_code=401,
            )
        except Exception:
            # The protocol's own rule (keystone_mcp/login/protocol.py): any
            # exception other than LoginRejected is the provider being
            # unavailable or buggy, not the credentials being wrong — logged
            # with a traceback, shown to the user the same as a bad
            # credential since there is no more specific page for this form.
            logger.exception("unexpected error from login provider %s", form_provider.name)
            await self._login_failure_limiter.record_failure(email, client_ip)
            client = await self._store.get_client(pending.client_id)
            if client is None:
                return self._html_error(request, lang, "error_request", 400)
            return self._render_consent_page(
                request,
                txn_id,
                lang,
                pending,
                client,
                error_key="error_invalid",
                status_code=401,
            )

        verified_identity = self._verify_identity_route(identity, form_provider.name)
        if verified_identity is None:
            await self._login_failure_limiter.record_failure(email, client_ip)
            client = await self._store.get_client(pending.client_id)
            if client is None:
                return self._html_error(request, lang, "error_request", 400)
            return self._render_consent_page(
                request,
                txn_id,
                lang,
                pending,
                client,
                error_key="error_invalid",
                status_code=401,
            )
        identity = verified_identity

        # Token-only verification is not enough: the holder of a shared
        # DEV-token (or an auth-service-issued one) could otherwise sign in
        # as any email, including one that does not belong to a real person.
        # The directory is consulted only after the token checks out, since
        # without a valid token there is nothing to authorize a lookup of
        # which emails the directory knows about.
        if self._user_resolver is not None:
            try:
                resolved = await self._user_resolver.resolve(identity.email)
            except UserDirectoryUnavailableError:
                client = await self._store.get_client(pending.client_id)
                if client is None:
                    return self._html_error(request, lang, "error_request", 400)
                return self._render_consent_page(
                    request,
                    txn_id,
                    lang,
                    pending,
                    client,
                    error_key="error_directory_unavailable",
                    status_code=503,
                )
            if not resolved.exists or resolved.is_blocked:
                await self._login_failure_limiter.record_failure(identity.email, client_ip)
                client = await self._store.get_client(pending.client_id)
                if client is None:
                    return self._html_error(request, lang, "error_request", 400)
                return self._render_consent_page(
                    request,
                    txn_id,
                    lang,
                    pending,
                    client,
                    error_key="error_user_denied",
                    status_code=403,
                )
        # Reachable whenever no directory resolver is wired at all, which is
        # not only a test path: server.py only builds one when RBAC is on,
        # Google sign-in is enabled, or DEV tokens are configured for
        # api_key sign-in against a ready local/http users backend
        # (local_users_directory_ready and dev_tokens_configured in
        # build_server). With RBAC off, Google disabled and no DEV tokens,
        # a real server runs this branch too, and a token-login email is
        # accepted without ever being checked against the directory.

        return await self._complete_login(
            txn_id,
            identity,
            lang,
            auth_method=form_provider.name,
            interactive=form_provider.interactive,
        )

    async def start_login_redirect_get(self, request: Request, name: str) -> Response:
        """``GET /login/{name}`` no longer redirects straight to the provider (A13).

        A bare link to this route used to skip the consent screen entirely;
        now it bounces to it (303) so the screen cannot be bypassed by a
        direct URL. Only reachable for a configured redirect provider: the
        route is not registered at all otherwise (server.py), so the
        defensive 404 below only guards against a provider disabled after
        this route was registered (e.g. a future hot-reload).
        """
        lang = _pick_language(
            request, self._settings.login_default_lang, base_url=self._settings.base_url
        )
        provider = self._providers.get(name)
        if provider is None or provider.kind != "redirect":
            return self._html_error(request, lang, "error_provider_disabled", 404)

        txn_id = request.query_params.get("txn", "").strip()
        return RedirectResponse(
            url=f"/login?{urlencode({'txn': txn_id})}",
            status_code=303,
        )

    async def start_login_redirect(self, request: Request, name: str) -> Response:
        """Consent screen's provider button target: requires a matching CSRF pair.

        The double-submit cookie (``km_login_csrf``) is unreadable from another
        origin and is not sent on a cross-site POST under ``SameSite=Lax``, so a
        forged form submission cannot start a redirect sign-in on the victim's
        behalf.
        """
        lang = _pick_language(
            request, self._settings.login_default_lang, base_url=self._settings.base_url
        )
        provider = self._providers.get(name)
        if provider is None or provider.kind != "redirect":
            return self._html_error(request, lang, "error_provider_disabled", 404)

        origin_refusal = cross_site_origin_refusal(
            request, effective_allowed_hosts(self._settings)
        )
        if origin_refusal is not None:
            return origin_refusal

        allowed_ip, retry_ip = await self._login_throttle.acheck_ip(peer_host(request))
        if not allowed_ip:
            return login_throttle_response(retry_ip)

        form = await request.form()
        txn_id = str(form.get("txn", "")).strip()
        csrf_field = str(form.get("csrf", ""))
        csrf_cookie = request.cookies.get(self._csrf_cookie_name(), "")
        if not csrf_field or not csrf_cookie or not secrets.compare_digest(csrf_field, csrf_cookie):
            return self._html_error(request, lang, "error_request", 400)

        if await self._get_pending_txn(txn_id) is None:
            return self._html_error(request, lang, "error_request", 400)

        state = secrets.token_urlsafe(24)
        # Binds this round trip to the browser that started it (finding #1,
        # 0.4.0 A13/A17): only a hash travels through the external provider,
        # never the cookie value itself, in case the state envelope ever
        # leaked (it is opaque server-side state, but there is no reason to
        # carry the raw secret).
        csrf_hash = _hash_csrf_cookie(csrf_cookie)
        try:
            redirect = await provider.begin(state=state, callback_url=self._callback_url(name))
        except LoginRejected as exc:
            logger.info("login rejected by provider %s: %s", name, exc.reason)
            if exc.reason == "provider_unavailable":
                return self._html_error(request, lang, "error_provider_unavailable", 503)
            return self._html_error(request, lang, "error_request", 400)
        except Exception:
            # Mirrors the protocol's own rule, applied at the other end of
            # the round trip (handle_login_callback): any exception other
            # than LoginRejected means the provider itself is unavailable or
            # buggy, not that this particular attempt is invalid -- logged
            # with a traceback, shown to the user as a service outage rather
            # than a 500 with a stack trace.
            logger.exception("unexpected error from login provider %s", name)
            return self._html_error(request, lang, "error_provider_unavailable", 503)
        envelope = json.dumps(
            {
                "txn": txn_id,
                "provider": name,
                "attempt": dict(redirect.attempt),
                "csrf_hash": csrf_hash,
            }
        )
        await self._pending_store.put(
            _NS_LOGIN_ATTEMPT,
            state,
            envelope,
            self._settings.login_pending_txn_ttl_seconds,
        )
        return RedirectResponse(url=redirect.url, status_code=302)

    def _render_consent_page(
        self,
        request: Request,
        txn_id: str,
        lang: str,
        pending: _PendingAuthorization,
        client: OAuthClientInformationFull,
        *,
        error_key: str | None = None,
        status_code: int = 200,
    ) -> Response:
        """Build the consent screen and, if a redirect provider is configured, (re)issue its CSRF cookie.

        A fresh value is minted on every render (finding #4, second review):
        the cookie used to be reused whenever the request already carried one
        at least 32 characters long, from *any* source — including one an
        attacker planted (e.g. over a plain-http same-host endpoint, or a
        sibling subdomain able to set a cookie without the `__Host-` prefix).
        Reusing it meant the double-submit pair this cookie exists to make
        unguessable could be a value the attacker already knows.

        Trade-off this creates: re-rendering this same transaction in a second
        tab (or on an invalid-token retry, or a language switch) now
        overwrites the browser's cookie, so a page already open in a first tab
        holds a `csrf` form field that no longer matches it — submitting that
        stale tab's form 400s. Reloading the page (or re-opening the same
        `?txn=` link) always produces a matching pair again, so this is a
        "reload and retry" inconvenience, not a dead end.
        """
        csrf_token: str | None = None
        if any(provider.kind == "redirect" for provider in self._providers.values()):
            csrf_token = secrets.token_urlsafe(32)

        t = self._translation(lang)
        content = render_consent_page(
            lang=lang,
            t=t,
            brand=self._settings.login_brand,
            client_name=client.client_name,
            redirect_uri=str(pending.params.redirect_uri),
            redirect_location=_consent_redirect_location(str(pending.params.redirect_uri)),
            providers=self._build_provider_views(t),
            txn=txn_id,
            csrf=csrf_token,
            error_key=error_key,
            txn_query=self._txn_query(txn_id),
        )
        response = _html_response(content, status_code=status_code)
        self._maybe_set_lang_cookie(response, request, lang)
        if csrf_token is not None:
            response.set_cookie(
                self._csrf_cookie_name(),
                csrf_token,
                max_age=self._settings.login_pending_txn_ttl_seconds,
                path=self._csrf_cookie_path(),
                httponly=True,
                samesite="lax",
                secure=self._settings.base_url.startswith("https://"),
            )
        return response

    async def handle_login_callback(self, request: Request, name: str) -> Response:
        """``GET /login/{name}/callback``: hand the callback to the named redirect provider.

        Only reachable for a configured redirect provider (server.py
        registers this route per provider); the ``provider is None`` branch
        below is defensive, matching ``start_login_redirect``.
        """
        lang = _pick_language(
            request, self._settings.login_default_lang, base_url=self._settings.base_url
        )

        state = request.query_params.get("state", "").strip()
        if not state:
            return self._html_error(request, lang, "error_request", 400)

        raw = await self._pending_store.consume(_NS_LOGIN_ATTEMPT, state)
        if raw is None:
            return self._html_error(request, lang, "error_request", 400)

        attempt = _parse_login_attempt_raw(raw)
        if attempt is None or attempt.provider != name:
            return self._html_error(request, lang, "error_request", 400)

        provider = self._providers.get(name)
        if provider is None or provider.kind != "redirect":
            return self._html_error(request, lang, "error_request", 400)

        # Binds this callback to the browser that started the round trip
        # (finding #1, 0.4.0 A13/A17): without this, a browser that never
        # visited /login or POSTed /login/{name} — and so never holds the
        # matching km_login_csrf cookie — could still complete a sign-in
        # whose `state` it only received as a link (e.g. one an attacker
        # forwards from their own /login/{name} POST). `state` is already
        # consumed above regardless of the outcome; that is unchanged from
        # before this check and is fine, since it is a single-use nonce
        # either way. The login transaction itself (attempt.txn_id) is not
        # touched until _complete_login, below, so refusing here does not
        # burn it.
        callback_csrf_cookie = request.cookies.get(self._csrf_cookie_name(), "")
        if not callback_csrf_cookie or not secrets.compare_digest(
            _hash_csrf_cookie(callback_csrf_cookie), attempt.csrf_hash
        ):
            logger.warning("login callback refused: csrf cookie missing or mismatched")
            return self._html_error(request, lang, "error_request", 400)

        params = dict(request.query_params)
        try:
            identity = await provider.complete(
                params=params, callback_url=self._callback_url(name), attempt=attempt.attempt
            )
        except LoginRejected as exc:
            logger.info("login rejected by provider %s: %s", name, exc.reason)
            if exc.reason == "domain_not_allowed":
                return self._html_error(request, lang, "error_provider_domain", 403)
            if exc.reason == "email_unverified":
                return self._html_error(request, lang, "error_provider_unverified", 403)
            if exc.reason == "provider_unavailable":
                return self._html_error(request, lang, "error_provider_unavailable", 502)
            if exc.reason == "request_invalid":
                if "error" in params:
                    return self._html_error(request, lang, "error_provider_identity", 400)
                return self._html_error(request, lang, "error_request", 400)
            if exc.reason == "identity_invalid":
                return self._html_error(request, lang, "error_provider_identity", 400)
            return self._html_error(request, lang, "error_provider_identity", 400)
        except Exception:
            logger.exception("unexpected error from login provider %s", name)
            return self._html_error(request, lang, "error_provider_unavailable", 503)

        verified_identity = self._verify_identity_route(identity, name)
        if verified_identity is None:
            return self._html_error(request, lang, "error_request", 400)
        identity = verified_identity

        if self._user_resolver is None:
            logger.error(
                "login provider %s enabled but user directory resolver is not configured", name
            )
            return self._html_error(request, lang, "error_directory_unavailable", 503)

        try:
            resolved = await self._user_resolver.resolve(identity.email)
        except UserDirectoryUnavailableError:
            return self._html_error(request, lang, "error_directory_unavailable", 503)

        if not resolved.exists or resolved.is_blocked:
            return self._html_error(request, lang, "error_user_denied", 403)

        if self._identity_binder is not None and identity.issuer and identity.subject_id:
            try:
                prior_binding = await self._identity_binder.get_identity_binding(identity.email)
                binding = await self._identity_binder.bind_identity(
                    email=identity.email,
                    issuer=identity.issuer,
                    subject=identity.subject_id,
                )
            except UserDirectoryUnavailableError:
                return self._html_error(request, lang, "error_directory_unavailable", 503)
            except IdentityBindingConflictError:
                if self._observability is not None:
                    self._observability.record_login_identity_binding(outcome="conflict")
                    self._observability.record_session_event(
                        action="identity_mismatch",
                        subject=identity.subject_id,
                        client_id="",
                        login_provider=name,
                    )
                logger.warning(
                    "login identity binding conflict for provider %s",
                    name,
                )
                return self._html_error(request, lang, "error_user_denied", 403)

            matched = binding.issuer == identity.issuer and binding.subject == identity.subject_id
            if not matched:
                if self._observability is not None:
                    self._observability.record_login_identity_binding(outcome="mismatch")
                    self._observability.record_session_event(
                        action="identity_mismatch",
                        subject=identity.subject_id,
                        client_id="",
                        login_provider=name,
                    )
                logger.warning(
                    "login identity binding mismatch for provider %s",
                    name,
                )
                return self._html_error(request, lang, "error_user_denied", 403)

            if self._observability is not None:
                outcome = "matched" if prior_binding is not None else "bound"
                self._observability.record_login_identity_binding(outcome=outcome)

        return await self._complete_login(
            attempt.txn_id, identity, lang, auth_method=name, interactive=provider.interactive
        )

    async def _complete_login(
        self,
        txn_id: str,
        identity: LoginIdentity,
        lang: str,
        *,
        auth_method: str,
        interactive: bool,
    ) -> Response:
        pending = await self._consume_pending_txn(txn_id)
        if pending is None:
            return self._html_error(None, lang, "error_request", 400)

        params = pending.params
        code_str = f"km_code_{secrets.token_urlsafe(24)}"
        auth_code = AuthorizationCode(
            code=code_str,
            scopes=params.scopes or [],
            expires_at=time.time() + self._settings.auth_code_ttl_seconds,
            client_id=pending.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=identity.email,
        )
        auth_time = int(time.time())
        key_id_known = auth_method == "api_key"
        key_expires_at: int | None = None
        if key_id_known and identity.key_expires_at is not None:
            key_expires_at = int(identity.key_expires_at.timestamp())
        await self._put_auth_code(
            auth_code,
            auth_method=auth_method,
            interactive=interactive,
            auth_time=auth_time,
            key_id=identity.key_id if key_id_known else None,
            key_id_known=key_id_known,
            key_expires_at=key_expires_at,
        )
        redirect_to = construct_redirect_uri(
            str(params.redirect_uri), code=code_str, state=params.state
        )
        return RedirectResponse(url=redirect_to, status_code=302)

    async def _put_refresh_meta(
        self,
        refresh_token: str,
        meta: RefreshMeta,
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        """Hold session metadata for the refresh token's lifetime.

        ``ttl_seconds`` is overridden to a short grace period when rotation
        rewrites the *old* token's marker instead of deleting it outright
        (finding #2, see ``exchange_refresh_token``).
        """
        ttl = ttl_seconds if ttl_seconds is not None else self._settings.refresh_token_ttl_seconds
        await self._pending_store.put(
            _NS_REFRESH_AUTH, refresh_token, encode_refresh_meta(meta), ttl
        )

    async def _read_refresh_meta(self, refresh_token: str) -> RefreshMeta | None:
        """Return parsed session metadata for a refresh token's marker."""
        digest = token_digest(refresh_token)
        raw = await self._pending_store.get(_NS_REFRESH_AUTH, digest)
        if raw is None:
            raw = await self._pending_store.get(_NS_REFRESH_AUTH, refresh_token)
        return parse_refresh_meta(raw)


def _parse_pending_txn_raw(raw: str) -> _PendingAuthorization | None:
    client_id, _, params_json = raw.partition("\n")
    if not client_id or not params_json:
        return None
    try:
        params = AuthorizationParams.model_validate_json(params_json)
    except ValidationError:
        return None
    return _PendingAuthorization(client_id, params)


def _encode_auth_code_envelope(
    code: AuthorizationCode,
    auth_method: str,
    interactive: bool,
    *,
    auth_time: int | None = None,
    key_id: str | None = None,
    key_id_known: bool = False,
    key_expires_at: int | None = None,
) -> str:
    payload: dict[str, object] = {
        "code": code.model_dump(mode="json"),
        "auth_method": auth_method,
        "interactive": interactive,
    }
    if auth_time is not None:
        payload["auth_time"] = auth_time
    if key_id_known:
        payload["key_id"] = key_id
        if key_expires_at is not None:
            payload["key_expires_at"] = key_expires_at
    return json.dumps(payload)


def _parse_auth_code_envelope(raw: str) -> _AuthCodeEnvelope | None:
    """Parse an authorization-code envelope, bridging pre-0.5.0 shapes.

    - Current shape: ``{"code", "auth_method", "interactive"}``.
    - 0.4.0 shape: ``{"code", "auth_method"}`` with no ``interactive`` key --
      rebuilt from the sign-in method's own name (``interactive = auth_method
      == "google"``), the same rule ``has_interactive_human_identity`` uses
      for a token minted before this claim existed.
    - Oldest (3.x) shape: a bare ``AuthorizationCode`` with no envelope at
      all -- ``auth_method`` defaults to ``"api_key"`` (never interactive),
      exactly as before this change.
    """
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict) and "code" in payload:
        try:
            code = AuthorizationCode.model_validate(payload["code"])
        except ValidationError:
            return None
        auth_method = str(payload.get("auth_method", "api_key")).strip() or "api_key"
        if "interactive" in payload:
            interactive = payload["interactive"] is True
        else:
            interactive = auth_method == "google"
        auth_time_raw = payload.get("auth_time")
        auth_time = (
            auth_time_raw
            if isinstance(auth_time_raw, int) and not isinstance(auth_time_raw, bool)
            else None
        )
        key_id_known = "key_id" in payload
        key_id = payload.get("key_id") if key_id_known else None
        if key_id is not None and not isinstance(key_id, str):
            key_id = None
        key_expires_raw = payload.get("key_expires_at")
        key_expires_at = (
            key_expires_raw
            if isinstance(key_expires_raw, int) and not isinstance(key_expires_raw, bool)
            else None
        )
        return _AuthCodeEnvelope(
            code=code,
            auth_method=auth_method,
            interactive=interactive,
            auth_time=auth_time,
            key_id=key_id if key_id_known else None,
            key_id_known=key_id_known,
            key_expires_at=key_expires_at if key_id_known else None,
        )
    try:
        code = AuthorizationCode.model_validate_json(raw)
    except ValidationError:
        return None
    return _AuthCodeEnvelope(
        code=code,
        auth_method="api_key",
        interactive=False,
        auth_time=None,
        key_id=None,
        key_id_known=False,
        key_expires_at=None,
    )


def _parse_login_attempt_raw(raw: str) -> _LoginAttempt | None:
    """Parse a ``login_attempt`` envelope written by ``start_login_redirect``.

    Replaces the Google-only ``_parse_google_pending_raw``: the stored shape
    is now ``{"txn", "provider", "attempt", "csrf_hash"}`` for any redirect
    provider (X03).
    """
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    txn_id = str(payload.get("txn", "")).strip()
    provider_name = str(payload.get("provider", "")).strip()
    attempt = payload.get("attempt")
    if not isinstance(attempt, dict):
        return None
    # Required, not defaulted: an envelope written before this field existed
    # (a login already in flight across a deploy) has no csrf_hash to check
    # against, and treating that as "no restriction" would reopen finding #1
    # for exactly the in-flight logins a deploy is most likely to catch.
    # Failing them closed just means a re-click of the provider's button.
    csrf_hash = str(payload.get("csrf_hash", "")).strip()
    if not txn_id or not provider_name or not csrf_hash:
        return None
    return _LoginAttempt(
        txn_id, provider_name, {str(k): str(v) for k, v in attempt.items()}, csrf_hash
    )
