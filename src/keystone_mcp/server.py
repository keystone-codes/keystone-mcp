"""Assemble the hosted keystone-mcp FastMCP server.

Builds the FastMCP instance with the embedded OAuth provider, mounts the login
page (where the api_token is validated), wires the router engine + registry, and
registers the built-in tool catalog.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from keystone_mcp.adapters.users_admin import RoleSource
from keystone_mcp.auth.identity_provider import (
    AuthServiceIdentityProvider,
    IdentityProvider,
    StaticIdentityProvider,
)
from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
from keystone_mcp.auth.login_pending_store import (
    InMemoryLoginPendingStore,
    LoginPendingStore,
    build_login_pending_store,
)
from keystone_mcp.auth.oauth_store import (
    OAuthStore,
    build_shared_auth_stores,
)
from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.catalog import register_catalog
from keystone_mcp.config import (
    AUTH_SERVICE_URL_WITHOUT_TOKEN_ERROR,
    ConfigError,
    Settings,
    client_address_allowed,
    effective_allowed_hosts,
    load_settings,
    startup_warnings,
)
from keystone_mcp.env_file import load_env_file
from keystone_mcp.http.access_log import AccessLogMiddleware
from keystone_mcp.http.host_guard import HostGuardMiddleware
from keystone_mcp.http.readiness import ReadinessProbe
from keystone_mcp.observability import RbacObservability
from keystone_mcp.observability.logging import configure_logging
from keystone_mcp.rbac.catalog import (
    LIVE_PUBLISHED_NAMES_PATH,
    collect_live_tool_names,
    format_live_published_names,
)
from keystone_mcp.rbac.loader import PolicyLoadError, RbacPolicyManager
from keystone_mcp.rbac.policy import PolicyContractError
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.proxy_schema import load_proxy_schema_patches
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.throttle_middleware import ThrottleMiddleware
from keystone_mcp.router.tool_call_observability_middleware import (
    ToolCallObservabilityMiddleware,
)
from keystone_mcp.router.upstream import UpstreamRegistry, UpstreamUnavailableError
from keystone_mcp.surface.reconciler import SurfaceReconciler, surface_reconciler_lifespan
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.protocol import UserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.users.bootstrap import UsersBootstrapError, bootstrap_users_store
from keystone_mcp.users.db import UsersConfigError
from keystone_mcp.users.factory import build_users_store
from keystone_mcp.users.revision import InProcessRevisionWriter
from keystone_mcp.users.store import UsersStore

if TYPE_CHECKING:
    from keystone_mcp.user_directory.revision import RevisionReader

logger = logging.getLogger(__name__)

_reconciler_holder: dict[str, SurfaceReconciler | None] = {"reconciler": None}
_users_store_holder: dict[str, UsersStore | None] = {"store": None}


@asynccontextmanager
async def _keystone_lifespan(_server: FastMCP):
    async with surface_reconciler_lifespan(_reconciler_holder.get("reconciler")):
        yield {}


@dataclass(frozen=True, slots=True)
class UpstreamDiscoveryResult:
    """Outcome of upstream MCP tool discovery at startup."""

    counts: dict[str, int]
    failed: bool = False
    partial: bool = False
    # Namespace -> reason, for every configured upstream not in ``counts``.
    unavailable: dict[str, str] = field(default_factory=dict)

    @property
    def total_tools(self) -> int:
        return sum(self.counts.values())


def build_identity_provider(settings: Settings) -> IdentityProvider:
    """Select dev-token or auth-service introspection based on configuration.

    ``validate_settings`` already refuses an auth-service URL without a token at
    startup; the same check is repeated here as defence-in-depth for callers
    that assemble a server without going through ``load_settings``.
    """
    url = settings.auth_service_url.strip()
    token = settings.auth_service_token.strip()
    if url and not token:
        raise ConfigError(AUTH_SERVICE_URL_WITHOUT_TOKEN_ERROR)
    if url and token:
        logger.warning(
            "KEYSTONE_MCP_AUTH_SERVICE_URL / KEYSTONE_MCP_AUTH_SERVICE_TOKEN are deprecated "
            "and will be removed in 0.4.1; API keys move into the built-in users directory."
        )
        return AuthServiceIdentityProvider(url, token)
    return StaticIdentityProvider({token for token in settings.dev_tokens.split(",") if token})


def policy_role_source(policy_manager: RbacPolicyManager | None) -> RoleSource:
    """Build the ``users_*`` adapter's view of which role names are assignable.

    ``policy_manager`` is read lazily, on every call, rather than once here:
    ``build_server`` constructs it before the policy file is loaded
    (``bootstrap_rbac_policy`` runs later), and a ``SIGHUP`` hot-reload must be
    picked up by the next ``users_*`` call without rebuilding the adapter.
    """
    if policy_manager is None:
        return lambda: None

    def source() -> frozenset[str]:
        policy = policy_manager.active_policy
        if policy is None:
            raise PolicyLoadError("RBAC policy has not been loaded")
        return policy.role_names

    return source


def build_server(
    identity_provider: IdentityProvider | None = None,
    settings: Settings | None = None,
    register_builtin_catalog: bool = True,
    oauth_store: OAuthStore | None = None,
    login_pending_store: LoginPendingStore | None = None,
    user_resolver: UserDirectoryResolver | None = None,
    google_oidc_client: object | None = None,
    observability: RbacObservability | None = None,
    users_store: UsersStore | None = None,
) -> tuple[
    FastMCP,
    RouterRegistry,
    KeystoneOAuthProvider,
    UpstreamRegistry,
    RbacPolicyManager | None,
    RbacObservability,
    SurfaceReconciler | None,
]:
    """Construct the server. Returns (mcp, registry, oauth_provider, upstreams, policy_manager, observability).

    The registry/provider are returned so tests can flip route modes, inspect
    routes, and seed valid tokens.
    """
    settings = settings or load_settings()
    if identity_provider is None:
        identity_provider = build_identity_provider(settings)

    if oauth_store is None:
        store, pending_store = build_shared_auth_stores(settings)
    elif login_pending_store is not None:
        store = oauth_store
        pending_store = login_pending_store
    else:
        # An injected OAuth store means an embedding process (or a test) is
        # supplying persistence. Pair the pending store with it: share its Redis
        # pool when it has one, and otherwise stay in memory alongside it rather
        # than going through the factory, which requires Redis.
        store = oauth_store
        if getattr(store, "redis", None) is not None:
            pending_store = build_login_pending_store(settings, oauth_store=store)
        else:
            pending_store = InMemoryLoginPendingStore()

    # The built-in users directory is built whenever it is the configured
    # backend, independent of Google login / RBAC: it is also where the
    # initial administrator is seeded at startup (bootstrap_platform) and,
    # in a later card, where DEV-token login looks a caller's email up.
    shared_revision: InMemoryRevisionReader | None = None
    if settings.users_directory_is_local and users_store is None:
        if settings.redis_url.strip():
            users_store = build_users_store(settings)
        else:
            # No Redis: close the "mutation -> new revision -> cache cleared"
            # loop in-process instead, sharing one counter between the store's
            # revision writer and the resolver's revision reader.
            shared_revision = InMemoryRevisionReader()
            users_store = build_users_store(
                settings, revision_writer=InProcessRevisionWriter(shared_revision.bump)
            )
    _users_store_holder["store"] = users_store

    # An explicitly-injected resolver (tests, or an embedding process wiring
    # its own) is always honored: only the *automatic* construction below is
    # gated (U02's decision, extended by A04). Token-based login's directory
    # check (A01) relies on this — a caller (or test) that wants the check
    # active with Google, RBAC and DEV tokens all off supplies its own
    # resolver.
    #
    # A04 coordinator finding: with RBAC_MODE=off and no Google (the `local`
    # profile's common case), the gate below used to stay closed, so a DEV
    # token let its holder sign in as *any* email — the users directory was
    # never consulted. Fixed narrowly: the gate also opens whenever DEV
    # tokens are configured for api_key sign-in, so a DEV token still only
    # admits people the directory lists. It does not open for every api_key
    # deployment (the card's literal wording), because most of this test
    # suite builds a server with api_key sign-in enabled, local backend, but
    # a *test* identity provider standing in for a real one and no
    # KEYSTONE_MCP_DEV_TOKENS set at all — the vulnerability this closes does
    # not apply there, and auto-building a resolver for them would demand an
    # unrelated, repo-wide rewrite of every such test's login fixtures.
    dev_tokens_configured = bool({t for t in settings.dev_tokens.split(",") if t.strip()})
    local_users_directory_ready = settings.users_backend == "local" or (
        settings.users_backend == "http" and settings.users_service_url.strip()
    )
    directory_resolver: UserDirectoryResolver | None = user_resolver
    if directory_resolver is None and (
        settings.google_login_enabled
        or settings.rbac_enabled
        or (
            settings.api_key_login_enabled and dev_tokens_configured and local_users_directory_ready
        )
    ):
        directory_resolver = build_user_directory_resolver(
            settings,
            users_store=users_store,
            revision_reader=shared_revision,
        )

    # Built before the OAuth provider (rather than alongside registry/upstream
    # wiring further down) so the provider itself can record client
    # registration metrics (KEYSTONE_MCP_OAUTH_MAX_CLIENTS, A12).
    # ``upstreams`` is constructed further down (it needs ``mcp``, which needs
    # ``oauth``, which needs ``rbac_observability``, which needs
    # ``policy_manager`` -- so ``upstreams`` cannot exist yet here). This
    # closure only reads the name at call time (``bootstrap_platform``, well
    # after ``build_server`` has returned and ``upstreams`` is fully
    # populated), so the forward reference to a not-yet-assigned local is safe
    # (P06).
    policy_manager = (
        RbacPolicyManager(settings, upstream_catalog_state=lambda: upstreams.catalog_state())
        if settings.rbac_enabled
        else None
    )
    rbac_observability = observability or RbacObservability(
        settings,
        policy_manager=policy_manager,
    )

    oauth = KeystoneOAuthProvider(
        identity_provider,
        settings,
        store,
        pending_store,
        user_resolver=directory_resolver,
        google_oidc_client=google_oidc_client,
        observability=rbac_observability,
    )
    mcp = FastMCP(name="keystone-mcp", auth=oauth, lifespan=_keystone_lifespan)

    # Login page: GET renders the credential form, POST validates the api_token
    # and issues the authorization code (no code on failure).
    @mcp.custom_route("/login", methods=["GET"])
    async def _login_get(request):  # noqa: ANN001
        return await oauth.render_login(request)

    @mcp.custom_route("/login", methods=["POST"])
    async def _login_post(request):  # noqa: ANN001
        return await oauth.handle_login(request)

    @mcp.custom_route("/login/google", methods=["GET"])
    async def _login_google(request):  # noqa: ANN001
        return await oauth.start_google_login(request)

    # Consent screen's "Sign in with Google" button posts here (CSRF-checked)
    # instead of following a bare link, so the federated-login redirect cannot
    # be triggered from a cross-site page or an emailed URL (A13).
    @mcp.custom_route("/login/google", methods=["POST"])
    async def _login_google_post(request):  # noqa: ANN001
        return await oauth.start_google_login_post(request)

    @mcp.custom_route("/login/google/callback", methods=["GET"])
    async def _login_google_callback(request):  # noqa: ANN001
        return await oauth.handle_google_callback(request)

    # Where authorize() sends a request whose redirect_uri host is not on
    # KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS (A17): a local error page
    # instead of a redirect carrying `error`/`state` to that disallowed host.
    @mcp.custom_route("/login/redirect-not-allowed", methods=["GET"])
    async def _login_redirect_not_allowed(request):  # noqa: ANN001
        return await oauth.render_redirect_not_allowed(request)

    throttle = PerIdentityThrottle(settings.throttle_max_requests, settings.throttle_window_seconds)
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, mcp)
    upstreams = UpstreamRegistry(
        main_mcp=mcp,
        registry=registry,
        tool_timeout_seconds=settings.upstream_tool_timeout_seconds,
        discovery_timeout_seconds=settings.upstream_discovery_timeout_seconds,
        tool_timeout_overrides=dict(settings.upstream_tool_timeouts),
        schema_patches=load_proxy_schema_patches(settings.proxy_schema_patches_path),
        status_envelope=settings.proxy_status_envelope,
        discovery_retries=settings.upstream_discovery_retries,
        refresh_enabled=settings.refresh_interval_seconds > 0,
    )
    upstreams.observability = rbac_observability

    if settings.internal_endpoints_enabled:

        @mcp.custom_route(LIVE_PUBLISHED_NAMES_PATH, methods=["GET"])
        async def _live_published_names(request):  # noqa: ANN001
            from starlette.responses import Response

            denied = _reject_untrusted_internal_caller(request, settings)
            if denied is not None:
                return denied

            body = format_live_published_names(collect_live_tool_names(registry))
            return Response(content=body, media_type="text/plain; charset=utf-8")

    if register_builtin_catalog:
        register_catalog(
            registry,
            settings,
            observability=rbac_observability,
            users_store=users_store,
            role_source=policy_role_source(policy_manager),
        )
        _warn_if_admin_tools_are_unguarded(registry, settings)

    _register_default_upstreams(upstreams, settings)

    # Throttling is enforced here and nowhere else, so one tool call consumes
    # exactly one slot whatever the RBAC mode. Added first, so it runs outermost
    # and a throttled identity never reaches the user directory.
    mcp.add_middleware(ThrottleMiddleware(throttle, observability=rbac_observability))

    if policy_manager is not None:
        # rbac_enabled implies the resolver was built above.
        assert directory_resolver is not None
        mcp.add_middleware(
            RbacMiddleware(
                policy_manager,
                directory_resolver,
                settings=settings,
                observability=rbac_observability,
            )
        )

    mcp.add_middleware(
        ToolCallObservabilityMiddleware(observability=rbac_observability),
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def _healthz(_request):  # noqa: ANN001
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok"})

    readiness_probe = ReadinessProbe(
        redis=getattr(store, "redis", None),
        policy_manager=policy_manager,
        users_backend=getattr(directory_resolver, "backend", None),
    )

    @mcp.custom_route("/readyz", methods=["GET"])
    async def _readyz(request):  # noqa: ANN001
        from starlette.responses import JSONResponse

        report = await readiness_probe.run()
        body: dict[str, object] = {"status": "ok" if report.ready else "degraded"}
        if _is_trusted_internal_caller(request, settings):
            body["checks"] = dict(report.checks)
        return JSONResponse(body, status_code=200 if report.ready else 503)

    if settings.metrics_enabled:
        metrics_path = settings.metrics_path.strip() or "/metrics"

        @mcp.custom_route(metrics_path, methods=["GET"])
        async def _metrics(request):  # noqa: ANN001
            from starlette.responses import Response

            denied = _reject_untrusted_internal_caller(request, settings)
            if denied is not None:
                return denied

            body, content_type = rbac_observability.metrics_response()
            return Response(content=body, media_type=content_type)

    revision_reader: RevisionReader | None = None
    if directory_resolver is not None:
        revision_reader = getattr(directory_resolver, "_revision_reader", None)

    reconciler: SurfaceReconciler | None = None
    if settings.refresh_interval_seconds > 0:
        reconciler = SurfaceReconciler(
            settings=settings,
            registry=registry,
            upstreams=upstreams,
            policy_manager=policy_manager,
            observability=rbac_observability,
            revision_reader=revision_reader,
        )
    _reconciler_holder["reconciler"] = reconciler

    return mcp, registry, oauth, upstreams, policy_manager, rbac_observability, reconciler


def _reject_untrusted_internal_caller(request, settings: Settings):  # noqa: ANN001
    """Guard an unauthenticated internal endpoint, or return None to allow.

    These endpoints carry no credential, so the caller is judged by source
    address against ``KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS``. The absence of
    ``X-Forwarded-For`` used to be the only check, which is not a source check
    at all: any caller that could reach the port and simply omitted the header
    was served, and a proxy that does not add the header let the whole internet
    through. The header rejection is kept as an additional signal — a request
    that arrived through a public proxy is not an internal one even if its peer
    address is the proxy sitting inside the allowlist.
    """
    from starlette.responses import Response

    if request.headers.get("x-forwarded-for"):
        logger.warning(
            "refused internal endpoint %s: request carries X-Forwarded-For, "
            "so it was proxied from outside",
            request.url.path,
        )
        return Response(status_code=403, content="Forbidden")

    client_host = request.client.host if request.client else None
    if not client_address_allowed(client_host, settings.internal_allowed_cidrs):
        logger.warning(
            "refused internal endpoint %s for peer %s: not in "
            "KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS (%s)",
            request.url.path,
            client_host or "<unknown>",
            ",".join(settings.internal_allowed_cidrs) or "<empty>",
        )
        return Response(status_code=403, content="Forbidden")

    return None


def _is_trusted_internal_caller(request, settings: Settings) -> bool:  # noqa: ANN001
    """Whether ``/readyz`` should include per-check detail for this caller.

    Unlike ``/metrics`` and the other internal endpoints, ``/readyz`` itself is
    never refused: a load balancer or container healthcheck polling from
    outside ``KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`` still gets the coarse
    ``ok``/``degraded`` status, just without ``checks``. There is also no
    WARNING log on a "no" here (unlike :func:`_reject_untrusted_internal_caller`),
    because that poll happens every few seconds from every replica.
    """
    if request.headers.get("x-forwarded-for"):
        return False
    client_host = request.client.host if request.client else None
    return client_address_allowed(client_host, settings.internal_allowed_cidrs)


def _warn_if_admin_tools_are_unguarded(registry: RouterRegistry, settings: Settings) -> None:
    """Log how built-in ``users_*`` admin tools relate to the current RBAC mode.

    Those routes are published only in ``enforce`` mode. In ``off`` or
    ``observe``, startup should say they are withheld rather than leaving the
    impression that user administration is available without authorization.
    """
    if settings.rbac_enforcing:
        return
    logger.warning(
        "KEYSTONE_MCP_RBAC_MODE=%s: built-in users_* admin tools are not "
        "published. Set KEYSTONE_MCP_RBAC_MODE=enforce with a policy to "
        "publish and authorize them.",
        settings.rbac_mode,
    )
    if settings.rbac_mode != "off":
        return
    admin_tools = sorted(route.published_name for route in registry.routes.values() if route.admin)
    if not admin_tools:
        return
    logger.warning(
        "KEYSTONE_MCP_RBAC_MODE=off and %d administrative tool(s) are published: %s. "
        "No authorization is enforced on them: any caller holding a valid access "
        "token may list and call them. Set KEYSTONE_MCP_RBAC_MODE=enforce with a "
        "policy to restrict them.",
        len(admin_tools),
        ", ".join(admin_tools),
    )


def _register_default_upstreams(upstreams: UpstreamRegistry, settings: Settings) -> None:
    for cfg in settings.upstreams:
        if not cfg.enabled:
            continue
        upstreams.add_upstream(
            cfg.name,
            cfg.url,
            namespace=cfg.namespace,
            tool_filter=cfg.build_tool_filter(),
            strip_prefix=cfg.strip_prefix,
            route_mode=cfg.route_mode,
            discovery_timeout_seconds=cfg.discovery_timeout_seconds,
            tool_timeout_seconds=cfg.tool_timeout_seconds,
            bearer_env=cfg.bearer_env,
        )


async def bootstrap_upstreams(
    upstreams: UpstreamRegistry,
    settings: Settings,
) -> UpstreamDiscoveryResult:
    """Discover downstream MCP tools, per upstream, tolerating individual failures.

    Each configured upstream is retried on its own (``UpstreamRegistry.discover_all``
    discovers them in parallel); one unreachable upstream never blocks the
    others, nor forces a retry of upstreams that already succeeded.
    """
    configured = [cfg.namespace for cfg in upstreams._upstreams]
    if not configured:
        return UpstreamDiscoveryResult(counts={})

    try:
        counts = await upstreams.discover_all()
    except Exception as exc:  # only a replaced discover_all can still raise
        counts = {}
        for namespace in configured:
            upstreams.mark_unavailable(namespace, f"{type(exc).__name__}: {exc}")

    for namespace in counts:
        upstreams.mark_available(namespace)  # idempotent; covers a replaced discover_all

    reasons = upstreams.unavailable_namespaces()
    unavailable = {
        namespace: reasons.get(namespace, "not discovered")
        for namespace in configured
        if namespace not in counts
    }
    failed = len(unavailable) == len(configured)

    partial = any(count == 0 for count in counts.values())
    if partial:
        logger.warning(
            "upstream discovery partial: some namespaces reported zero tools: %s",
            counts,
        )
    if unavailable and not failed:
        logger.warning(
            "upstream discovery: %d of %d upstream(s) unavailable (%s); proxying the rest",
            len(unavailable),
            len(configured),
            ", ".join(f"{ns}: {reason}" for ns, reason in sorted(unavailable.items())),
        )
    if failed:
        logger.warning(
            "upstream discovery failed for every configured upstream: %s",
            ", ".join(f"{ns}: {reason}" for ns, reason in sorted(unavailable.items())),
        )

    return UpstreamDiscoveryResult(
        counts=counts, failed=failed, partial=partial, unavailable=unavailable
    )


def bootstrap_rbac_policy(
    policy_manager: RbacPolicyManager | None,
    registry: RouterRegistry,
    *,
    discovery: UpstreamDiscoveryResult | None = None,
    observability: RbacObservability | None = None,
) -> None:
    """Load and validate RBAC policy against the discovered live catalog.

    Fail-fast (raises :class:`PolicyLoadError`) when:
    - the policy file is missing or unreadable;
    - YAML/structure validation fails (:class:`PolicyContractError`);
    - the live catalog gate fails (an allow pattern matches no known tool);
    - ``rbac_enabled`` and upstream discovery fully failed (empty catalog while
      upstreams are configured).

    Tools no role can reach are logged as a WARNING, not refused.

    Hot-reload failures are non-fatal (see :meth:`RbacPolicyManager.reload`).
    """
    if policy_manager is None:
        return
    try:
        policy_manager.load_initial(
            registry,
            discovery_counts=discovery.counts if discovery is not None else None,
        )
        if observability is not None:
            observability.record_policy_reload(success=True)
    except PolicyContractError as exc:
        if observability is not None:
            observability.record_policy_reload(success=False)
        raise PolicyLoadError(str(exc)) from exc


def install_policy_reload_signal(
    registry: RouterRegistry,
    policy_manager: RbacPolicyManager | None,
    *,
    observability: RbacObservability | None = None,
    reconciler: SurfaceReconciler | None = None,
) -> None:
    """Register SIGHUP to queue RBAC policy reload on the reconciler loop."""
    if policy_manager is None:
        return
    if not hasattr(signal, "SIGHUP"):
        logger.info("SIGHUP unavailable on this platform; RBAC hot-reload via signal disabled")
        return

    def _reload_policy_inline() -> None:
        result = policy_manager.reload(registry)
        if observability is not None:
            observability.record_policy_reload(success=result.success)
        if result.success:
            logger.info("rbac policy reloaded via SIGHUP")
        else:
            logger.warning("rbac policy SIGHUP reload rejected: %s", result.error)

    def _on_sighup(signum: int, frame: object | None) -> None:  # noqa: ARG001
        if reconciler is not None and reconciler.request_policy_reload():
            return
        _reload_policy_inline()

    signal.signal(signal.SIGHUP, _on_sighup)
    logger.info("rbac policy SIGHUP hot-reload handler installed")


async def bootstrap_platform(
    upstreams: UpstreamRegistry,
    registry: RouterRegistry,
    settings: Settings,
    policy_manager: RbacPolicyManager | None,
    *,
    observability: RbacObservability | None = None,
    users_store: UsersStore | None = None,
) -> UpstreamDiscoveryResult:
    """Migrate/seed the users directory, discover upstreams, then load RBAC policy."""
    if users_store is not None:
        await bootstrap_users_store(users_store, settings)
    discovery = await bootstrap_upstreams(upstreams, settings)
    if settings.upstream_require_all and discovery.unavailable:
        raise UpstreamUnavailableError(
            "KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true and upstream(s) unavailable: "
            + ", ".join(f"{ns} ({reason})" for ns, reason in sorted(discovery.unavailable.items()))
        )
    if settings.rbac_enabled and discovery.failed:
        raise PolicyLoadError(
            "upstream discovery failed for every configured upstream with "
            "rbac_enabled=true; refusing to start: "
            + ", ".join(f"{ns} ({reason})" for ns, reason in sorted(discovery.unavailable.items()))
        )
    bootstrap_rbac_policy(
        policy_manager,
        registry,
        discovery=discovery,
        observability=observability,
    )
    return discovery


def _http_asgi_middleware(settings: Settings) -> list:
    """Starlette middleware passed to FastMCP HTTP transport.

    ``HostGuardMiddleware`` is listed first (first = outermost of *this*
    list) so a disallowed ``Host``/``Origin`` is refused before access
    logging runs for that request, and — more importantly — before any
    route's own handler does: this list is appended after fastmcp's own
    auth middleware (bearer-token parsing) in the final stack, but still
    wraps the router, so no OAuth endpoint, ``/mcp`` call, or custom route
    ever executes for a request this guard refuses (finding #1).
    """
    from starlette.middleware import Middleware

    stack: list = [Middleware(HostGuardMiddleware, allowed_hosts=effective_allowed_hosts(settings))]
    if settings.log_access_enabled:
        stack.append(Middleware(AccessLogMiddleware, settings=settings))
    return stack


def main() -> None:
    env_result = load_env_file()
    settings = load_settings()
    configure_logging(settings)
    logger.info("deployment profile: %s", settings.deployment_profile)
    for warning in startup_warnings(settings):
        logger.warning(warning)
    if env_result.path is not None:
        logger.info("loaded %d settings from %s", len(env_result.loaded), env_result.path)
    if not settings.oauth_dcr_enabled:
        logger.info(
            "dynamic client registration is disabled; register OAuth clients "
            "manually (docs/environment.md#registering-a-client-manually)"
        )
    try:
        mcp, registry, _oauth, upstreams, policy_manager, observability, reconciler = build_server(
            settings=settings,
        )
    except UsersConfigError as exc:
        logger.error(str(exc))
        raise SystemExit(1) from exc

    users_store = _users_store_holder["store"]
    try:
        asyncio.run(
            bootstrap_platform(
                upstreams,
                registry,
                settings,
                policy_manager,
                observability=observability,
                users_store=users_store,
            )
        )
    except UsersBootstrapError as exc:
        logger.error(str(exc))
        raise SystemExit(1) from exc
    install_policy_reload_signal(
        registry,
        policy_manager,
        observability=observability,
        reconciler=reconciler,
    )
    mcp.run(
        transport="http",
        host=settings.host,
        port=settings.port,
        path=settings.http_path,
        middleware=_http_asgi_middleware(settings) or None,
        uvicorn_config={"access_log": False},
    )


if __name__ == "__main__":
    main()
