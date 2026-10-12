"""Generic OpenID Connect redirect login provider with discovery."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote_plus, urlencode, urlparse

import httpx
import jwt
from jwt import PyJWKSet

from keystone_mcp.login.protocol import LoginIdentity, LoginRedirect, LoginRejected

logger = logging.getLogger(__name__)

_RESERVED_AUTHORIZE_PARAMS = frozenset(
    {
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
)

_ALLOWED_ID_TOKEN_ALGS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

GOOGLE_OIDC_ISSUER = "https://accounts.google.com"


@dataclass(frozen=True, slots=True)
class OidcProviderConfig:
    name: str
    title: str
    issuer: str
    client_id: str
    client_secret: str
    scopes: tuple[str, ...] = ("openid", "email")
    allowed_domains: tuple[str, ...] = ()
    hosted_domain: str | None = None
    email_claim: str = "email"
    require_email_verified: bool = True
    groups_claim: str | None = None
    extra_authorize_params: Mapping[str, str] = field(default_factory=dict)
    additional_issuers: tuple[str, ...] = ()
    token_auth_method: Literal["client_secret_basic", "client_secret_post"] | None = None


@dataclass(frozen=True, slots=True)
class _DiscoveryDocument:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    id_token_signing_alg_values_supported: tuple[str, ...] = ()
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()


def google_provider_config(
    *,
    client_id: str,
    client_secret: str,
    allowed_domain: str = "",
    name: str = "google",
    title: str = "Google",
) -> OidcProviderConfig:
    domain = allowed_domain.strip().lower().lstrip("@")
    hosted = domain or None
    allowed = (domain,) if domain else ()
    return OidcProviderConfig(
        name=name,
        title=title,
        issuer=GOOGLE_OIDC_ISSUER,
        client_id=client_id.strip(),
        client_secret=client_secret.strip(),
        additional_issuers=("accounts.google.com",),
        scopes=("openid", "email"),
        extra_authorize_params={"prompt": "select_account"},
        token_auth_method="client_secret_post",
        hosted_domain=hosted,
        allowed_domains=allowed,
    )


def is_builtin_google_provider(provider: object) -> bool:
    if not isinstance(provider, OidcLoginProvider):
        return False
    return provider.config.name == "google" and provider.config.issuer == GOOGLE_OIDC_ISSUER


def _issuer_url_allowed(issuer: str) -> bool:
    parsed = urlparse(issuer.strip())
    if parsed.scheme == "https":
        return bool(parsed.netloc)
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        return host in {"localhost", "127.0.0.1", "::1"}
    return False


def _default_port(scheme: str) -> int | None:
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _url_origin_key(url: str) -> tuple[str, str, int] | None:
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return None
    port = parsed.port if parsed.port is not None else _default_port(scheme)
    if port is None:
        return None
    return scheme, host, port


def _validate_discovery_endpoint_origin(
    *,
    provider_name: str,
    configured_issuer: str,
    endpoint_url: str,
    field_name: str,
) -> None:
    issuer_origin = _url_origin_key(configured_issuer)
    endpoint_origin = _url_origin_key(endpoint_url)
    if issuer_origin is None or endpoint_origin is None:
        logger.error(
            "login provider %s: discovery %s has invalid URL",
            provider_name,
            field_name,
        )
        raise LoginRejected("provider_unavailable", "discovery endpoint origin mismatch")

    issuer_scheme, _, _ = issuer_origin
    endpoint_scheme, _, _ = endpoint_origin
    if issuer_scheme == "https" and endpoint_scheme != "https":
        logger.error(
            "login provider %s: discovery %s scheme mismatch",
            provider_name,
            field_name,
        )
        raise LoginRejected("provider_unavailable", "discovery endpoint origin mismatch")
    if issuer_scheme == "http" and endpoint_scheme != "http":
        logger.error(
            "login provider %s: discovery %s scheme mismatch",
            provider_name,
            field_name,
        )
        raise LoginRejected("provider_unavailable", "discovery endpoint origin mismatch")

    if issuer_origin != endpoint_origin:
        logger.error(
            "login provider %s: discovery %s host or port mismatch",
            provider_name,
            field_name,
        )
        raise LoginRejected("provider_unavailable", "discovery endpoint origin mismatch")


def _new_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def _append_query(url: str, params: Mapping[str, str]) -> str:
    encoded = urlencode(params)
    if not encoded:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{encoded}"


class OidcLoginProvider:
    """Redirect-kind login via OIDC discovery, PKCE, and id_token verification."""

    def __init__(
        self,
        config: OidcProviderConfig,
        *,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
        cache_ttl_seconds: float = 3600.0,
        clock_skew_seconds: int = 60,
    ) -> None:
        if "openid" not in config.scopes:
            raise ValueError(f"login provider {config.name!r}: scopes must include 'openid'")
        for key in config.extra_authorize_params:
            if key in _RESERVED_AUTHORIZE_PARAMS:
                raise ValueError(
                    f"login provider {config.name!r}: extra_authorize_params "
                    f"uses reserved key {key!r}"
                )
        if not _issuer_url_allowed(config.issuer):
            raise ValueError(
                f"login provider {config.name!r}: issuer must be https:// "
                f"(or http:// on loopback for local testing)"
            )
        self._config = config
        self._http_client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        )
        self._cache_ttl_seconds = cache_ttl_seconds
        self._clock_skew_seconds = clock_skew_seconds
        self._discovery_cache: tuple[float, _DiscoveryDocument] | None = None
        self._jwks_cache: tuple[float, PyJWKSet] | None = None

    @property
    def config(self) -> OidcProviderConfig:
        return self._config

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def kind(self) -> Literal["redirect"]:
        return "redirect"

    @property
    def title(self) -> str:
        return self._config.title

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        try:
            await self._load_discovery()
            await self._load_jwks()
        except LoginRejected as exc:
            if exc.reason == "provider_unavailable":
                logger.warning(
                    "login provider %s warm_up: %s",
                    self._config.name,
                    exc.args[0] if exc.args else exc.reason,
                )
            else:
                logger.warning("login provider %s warm_up failed: %s", self._config.name, exc)
        except Exception:
            logger.warning("login provider %s warm_up failed", self._config.name, exc_info=True)

    async def aclose(self) -> None:
        return None

    async def begin(self, *, state: str, callback_url: str) -> LoginRedirect:
        discovery = await self._load_discovery()
        nonce = secrets.token_urlsafe(24)
        verifier, challenge = _new_pkce_pair()
        params: dict[str, str] = {
            "client_id": self._config.client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if self._config.hosted_domain:
            params["hd"] = self._config.hosted_domain
        params.update(dict(self._config.extra_authorize_params))
        url = _append_query(discovery.authorization_endpoint, params)
        return LoginRedirect(url=url, attempt={"nonce": nonce, "verifier": verifier})

    async def complete(
        self, *, params: Mapping[str, str], callback_url: str, attempt: Mapping[str, str]
    ) -> LoginIdentity:
        if params.get("error"):
            raise LoginRejected("request_invalid", "identity provider returned an error")
        code = params.get("code", "").strip()
        if not code:
            raise LoginRejected("request_invalid", "missing authorization code")

        discovery = await self._load_discovery()
        verifier = attempt.get("verifier", "")
        expected_nonce = attempt.get("nonce", "")
        token_body = await self._exchange_code(
            discovery, code=code, redirect_uri=callback_url, code_verifier=verifier
        )
        id_token = str(token_body.get("id_token", "")).strip()
        if not id_token:
            raise LoginRejected("identity_invalid", "token response missing id_token")

        claims = await self._verify_id_token(discovery, id_token, expected_nonce=expected_nonce)
        email_raw = str(claims.get(self._config.email_claim, "")).strip().lower()
        if not email_raw or "@" not in email_raw:
            raise LoginRejected("identity_invalid", "id_token missing a usable email claim")

        if self._config.require_email_verified:
            verified = claims.get("email_verified")
            if verified is not True and not (
                isinstance(verified, str) and verified.lower() == "true"
            ):
                raise LoginRejected("email_unverified", "email not verified by provider")

        email_domain = email_raw.rsplit("@", 1)[-1]
        if self._config.allowed_domains and email_domain not in self._config.allowed_domains:
            raise LoginRejected("domain_not_allowed", "email domain not allowed")

        if self._config.hosted_domain:
            hd = claims.get("hd")
            hd_norm = str(hd).strip().lower() if hd is not None else ""
            if hd_norm != self._config.hosted_domain.strip().lower():
                raise LoginRejected("domain_not_allowed", "hosted domain claim mismatch")

        groups: tuple[str, ...] = ()
        if self._config.groups_claim:
            raw_groups = claims.get(self._config.groups_claim)
            if isinstance(raw_groups, list):
                groups = tuple(str(g) for g in raw_groups if isinstance(g, str))

        return LoginIdentity(
            email=email_raw,
            provider=self._config.name,
            interactive=True,
            groups=groups,
        )

    async def _load_discovery(self) -> _DiscoveryDocument:
        now = time.monotonic()
        if self._discovery_cache is not None:
            cached_at, doc = self._discovery_cache
            if now - cached_at < self._cache_ttl_seconds:
                return doc

        url = f"{self._config.issuer.rstrip('/')}/.well-known/openid-configuration"
        try:
            async with self._http_client_factory() as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            logger.error(
                "login provider %s: discovery request failed (%s)",
                self._config.name,
                type(exc).__name__,
            )
            raise LoginRejected("provider_unavailable", "discovery unavailable") from exc

        if response.status_code != 200:
            logger.error(
                "login provider %s: discovery returned status %s",
                self._config.name,
                response.status_code,
            )
            raise LoginRejected("provider_unavailable", "discovery unavailable")

        try:
            payload = response.json()
        except ValueError as exc:
            logger.error(
                "login provider %s: discovery response was not JSON (%s)",
                self._config.name,
                type(exc).__name__,
            )
            raise LoginRejected("provider_unavailable", "discovery unavailable") from exc

        if not isinstance(payload, dict):
            raise LoginRejected("provider_unavailable", "discovery unavailable")

        try:
            discovered_issuer = str(payload["issuer"])
            authorization_endpoint = str(payload["authorization_endpoint"])
            token_endpoint = str(payload["token_endpoint"])
            jwks_uri = str(payload["jwks_uri"])
        except KeyError as exc:
            logger.error(
                "login provider %s: discovery document missing field %s",
                self._config.name,
                exc.args[0],
            )
            raise LoginRejected("provider_unavailable", "discovery incomplete") from exc

        if discovered_issuer != self._config.issuer:
            logger.error(
                "login provider %s: issuer mismatch: configured %s, discovered %s",
                self._config.name,
                self._config.issuer,
                discovered_issuer,
            )
            raise LoginRejected("provider_unavailable", "issuer mismatch")

        for field_name, endpoint_url in (
            ("authorization_endpoint", authorization_endpoint),
            ("token_endpoint", token_endpoint),
            ("jwks_uri", jwks_uri),
        ):
            _validate_discovery_endpoint_origin(
                provider_name=self._config.name,
                configured_issuer=self._config.issuer,
                endpoint_url=endpoint_url,
                field_name=field_name,
            )

        algs_raw = payload.get("id_token_signing_alg_values_supported")
        if isinstance(algs_raw, list):
            algs = tuple(str(a) for a in algs_raw)
        else:
            algs = ()

        auth_methods_raw = payload.get("token_endpoint_auth_methods_supported")
        if isinstance(auth_methods_raw, list):
            auth_methods = tuple(str(m) for m in auth_methods_raw)
        else:
            auth_methods = ()

        doc = _DiscoveryDocument(
            issuer=discovered_issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            id_token_signing_alg_values_supported=algs,
            token_endpoint_auth_methods_supported=auth_methods,
        )
        self._discovery_cache = (now, doc)
        return doc

    async def _load_jwks(self, *, force_refresh: bool = False) -> PyJWKSet:
        discovery = await self._load_discovery()
        now = time.monotonic()
        if not force_refresh and self._jwks_cache is not None:
            cached_at, jwks = self._jwks_cache
            if now - cached_at < self._cache_ttl_seconds:
                return jwks

        try:
            async with self._http_client_factory() as client:
                response = await client.get(discovery.jwks_uri)
        except httpx.HTTPError as exc:
            logger.error(
                "login provider %s: JWKS request failed (%s)",
                self._config.name,
                type(exc).__name__,
            )
            raise LoginRejected("provider_unavailable", "jwks unavailable") from exc

        if response.status_code != 200:
            logger.error(
                "login provider %s: JWKS returned status %s",
                self._config.name,
                response.status_code,
            )
            raise LoginRejected("provider_unavailable", "jwks unavailable")

        try:
            body = response.json()
        except ValueError as exc:
            raise LoginRejected("provider_unavailable", "jwks unavailable") from exc

        jwks = PyJWKSet.from_dict(body)
        self._jwks_cache = (now, jwks)
        return jwks

    def _resolve_token_auth_method(self, discovery: _DiscoveryDocument) -> str:
        if self._config.token_auth_method is not None:
            return self._config.token_auth_method
        supported = discovery.token_endpoint_auth_methods_supported
        if not supported or "client_secret_basic" in supported:
            return "client_secret_basic"
        return "client_secret_post"

    async def _exchange_code(
        self,
        discovery: _DiscoveryDocument,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        form: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        headers: dict[str, str] = {}
        auth_method = self._resolve_token_auth_method(discovery)
        if auth_method == "client_secret_basic":
            cid = quote_plus(self._config.client_id, safe="")
            secret = quote_plus(self._config.client_secret, safe="")
            creds = f"{cid}:{secret}"
            token = base64.b64encode(creds.encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        else:
            form["client_id"] = self._config.client_id
            form["client_secret"] = self._config.client_secret

        try:
            async with self._http_client_factory() as client:
                response = await client.post(discovery.token_endpoint, data=form, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning(
                "login provider %s: token request failed (%s)",
                self._config.name,
                type(exc).__name__,
            )
            raise LoginRejected("identity_invalid", "token exchange failed") from exc

        if response.status_code != 200:
            error_code: str | None = None
            try:
                err_body = response.json()
                if isinstance(err_body, dict) and err_body.get("error") is not None:
                    error_code = str(err_body["error"])
            except ValueError:
                pass
            logger.warning(
                "login provider %s: token endpoint status=%s error=%s",
                self._config.name,
                response.status_code,
                error_code,
            )
            raise LoginRejected("identity_invalid", "token endpoint error")

        try:
            body = response.json()
        except ValueError as exc:
            raise LoginRejected("identity_invalid", "token response not JSON") from exc

        if not isinstance(body, dict):
            raise LoginRejected("identity_invalid", "token response invalid")
        return body

    def _allowed_algorithms(self, discovery: _DiscoveryDocument) -> frozenset[str]:
        if discovery.id_token_signing_alg_values_supported:
            supported = frozenset(discovery.id_token_signing_alg_values_supported)
            return supported & _ALLOWED_ID_TOKEN_ALGS
        return frozenset({"RS256"})

    async def _verify_id_token(
        self,
        discovery: _DiscoveryDocument,
        id_token: str,
        *,
        expected_nonce: str,
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as exc:
            logger.info(
                "login provider %s: id_token header invalid (%s)",
                self._config.name,
                type(exc).__name__,
            )
            raise LoginRejected("identity_invalid", "invalid id_token") from exc

        alg = str(header.get("alg", ""))
        if alg.lower() == "none" or alg.upper().startswith("HS"):
            raise LoginRejected("identity_invalid", "disallowed id_token algorithm")

        allowed_algs = self._allowed_algorithms(discovery)
        if alg not in allowed_algs:
            raise LoginRejected("identity_invalid", "id_token algorithm not allowed")

        kid = header.get("kid")
        signing_key = await self._lookup_signing_key_async(discovery, kid=kid)

        issuers = [self._config.issuer, *self._config.additional_issuers]
        try:
            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=[alg],
                audience=self._config.client_id,
                issuer=issuers,
                leeway=self._clock_skew_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as exc:
            logger.info(
                "login provider %s: id_token verification failed (%s)",
                self._config.name,
                type(exc).__name__,
            )
            raise LoginRejected("identity_invalid", "id_token verification failed") from exc

        token_nonce = claims.get("nonce")
        if not token_nonce or str(token_nonce) != expected_nonce:
            raise LoginRejected("identity_invalid", "id_token nonce mismatch")

        aud = claims.get("aud")
        azp = claims.get("azp")
        if isinstance(aud, list) and len(aud) > 1:
            if azp is None:
                raise LoginRejected("identity_invalid", "id_token missing azp")
            if str(azp) != self._config.client_id:
                raise LoginRejected("identity_invalid", "id_token azp mismatch")
        elif azp is not None and str(azp) != self._config.client_id:
            raise LoginRejected("identity_invalid", "id_token azp mismatch")

        if not isinstance(claims, dict):
            raise LoginRejected("identity_invalid", "id_token claims invalid")
        return claims

    async def _lookup_signing_key_async(
        self, discovery: _DiscoveryDocument, *, kid: str | None
    ) -> Any:
        jwks = await self._load_jwks()
        key = self._key_from_jwks(jwks, kid)
        if key is not None:
            return key
        jwks = await self._load_jwks(force_refresh=True)
        key = self._key_from_jwks(jwks, kid)
        if key is None:
            raise LoginRejected("identity_invalid", "signing key not found")
        return key

    @staticmethod
    def _key_from_jwks(jwks: PyJWKSet, kid: str | None) -> Any | None:
        for jwk in jwks.keys:
            if kid is None or jwk.key_id == kid:
                return jwk.key
        return None


def create_oidc_provider(config, context) -> OidcLoginProvider:
    from keystone_mcp.config import ConfigError
    from keystone_mcp.login.file_options import parse_oidc_options
    from keystone_mcp.plugins import LoginProviderConfig, PluginContext

    if not isinstance(config, LoginProviderConfig) or not isinstance(context, PluginContext):
        raise TypeError("invalid factory arguments")
    title = config.title if config.title is not None else config.name
    try:
        oidc_config = parse_oidc_options(
            config.options,
            name=config.name,
            title=title,
            deployment_profile=context.deployment_profile,
            secret=context.secret,
        )
    except ValueError as exc:
        raise ConfigError(f"login provider {config.name!r}: {exc}") from exc
    return OidcLoginProvider(oidc_config)


def create_google_provider(config, context) -> OidcLoginProvider:
    from keystone_mcp.config import ConfigError
    from keystone_mcp.login.file_options import parse_google_options
    from keystone_mcp.plugins import LoginProviderConfig, PluginContext

    if not isinstance(config, LoginProviderConfig) or not isinstance(context, PluginContext):
        raise TypeError("invalid factory arguments")
    title = config.title if config.title is not None else config.name
    try:
        oidc_config = parse_google_options(
            config.options,
            name=config.name,
            title=title,
            secret=context.secret,
        )
    except ValueError as exc:
        raise ConfigError(f"login provider {config.name!r}: {exc}") from exc
    return OidcLoginProvider(oidc_config)
