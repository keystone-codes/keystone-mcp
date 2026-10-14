"""Assemble the hosted keystone-mcp FastMCP server.

Builds the FastMCP instance with the embedded OAuth provider, mounts the login
page (where the api_token is validated), wires the router engine + registry, and
registers the built-in tool catalog.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from collections.abc import Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import mcp_types
from fastmcp import FastMCP

import keystone_mcp
from keystone_mcp.adapters.users_admin import RoleSource
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
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.catalog import register_catalog
from keystone_mcp.config import (
    ConfigError,
    Settings,
    client_address_allowed,
    effective_allowed_hosts,
    load_settings,
    startup_warnings,
)
from keystone_mcp.env_file import load_env_file
from keystone_mcp.http.access_log import AccessLogMiddleware
from keystone_mcp.http.host_guard import HostGuardMiddleware, host_allowed, host_allowlist_sets
from keystone_mcp.http.readiness import BootstrapState, ReadinessProbe
from keystone_mcp.login.factory import (
    api_key_login_configured,
    build_login_providers,
    check_login_providers_for_profile,
    login_providers_want_directory_resolver,
    validate_login_providers,
)
from keystone_mcp.login.protocol import LoginProvider
from keystone_mcp.observability import RbacObservability
from keystone_mcp.observability.logging import configure_logging, reapply_logger_levels
from keystone_mcp.rbac.catalog import (
    LIVE_PUBLISHED_NAMES_PATH,
    collect_live_tool_names,
    format_live_published_names,
)
from keystone_mcp.rbac.loader import PolicyLoadError, RbacPolicyManager, preflight_rbac_policy_file
from keystone_mcp.rbac.policy import PolicyContractError
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.proxy_schema import load_proxy_schema_patches
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.throttle_middleware import ThrottleMiddleware
from keystone_mcp.router.tool_call_observability_middleware import (
    ToolCallObservabilityMiddleware,
)
from keystone_mcp.router.upstream import UpstreamRegistry, UpstreamUnavailableError
from keystone_mcp.surface.client_sessions import (
    ClientSessionRegistry,
    SessionTrackingMiddleware,
)
from keystone_mcp.surface.reconciler import SurfaceReconciler, surface_reconciler_lifespan
from keystone_mcp.user_directory.factory import (
    build_user_directory,
    build_user_directory_resolver,
    validate_directory_capabilities,
)
from keystone_mcp.user_directory.protocol import UserDirectory, UserDirectoryResolver
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
_upstreams_holder: dict[str, UpstreamRegistry | None] = {"upstreams": None}
_users_store_holder: dict[str, UsersStore | None] = {"store": None}
_login_providers_holder: dict[str, list[LoginProvider] | None] = {"providers": None}
_client_sessions_holder: dict[str, ClientSessionRegistry | None] = {"registry": None}
#: The PolicyStore built by the most recent build_server() call, for whatever
#: wants to reach it outside the return tuple (a later card's policy_* tool
#: adapter, a CLI). None whenever RBAC does not enforce or POLICY_TOOLS=off.
_policy_store_holder: dict[str, PolicyStore | None] = {"store": None}
_session_revoker_holder: dict[str, SessionRevoker | None] = {"revoker": None}
_bootstrap_state_holder: dict[str, BootstrapState | None] = {"state": None}
_deferred_bootstrap_holder: dict[str, Callable[[], Awaitable[None]] | None] = {"factory": None}
_startup_failure_holder: dict[str, BaseException | None] = {"error": None}


def _default_request_shutdown() -> None:
    os.kill(os.getpid(), signal.SIGTERM)


_request_shutdown: Callable[[], None] = _default_request_shutdown


@asynccontextmanager
async def _keystone_lifespan(_server: FastMCP):
    reapply_logger_levels()
    upstreams = _upstreams_holder.get("upstreams")
    reconciler = _reconciler_holder.get("reconciler")
    deferred_factory = _deferred_bootstrap_holder.get("factory")
    bootstrap_task: asyncio.Task[None] | None = None
    try:
        if deferred_factory is not None:
            bootstrap_task = asyncio.create_task(deferred_factory(), name="keystone-bootstrap")
            yield {}
        else:
            if upstreams is not None:
                await upstreams.start_connections()
            async with surface_reconciler_lifespan(reconciler):
                yield {}
    finally:
        if bootstrap_task is not None and not bootstrap_task.done():
            bootstrap_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await bootstrap_task
        if deferred_factory is not None and reconciler is not None:
            await reconciler.stop()
        if upstreams is not None:
            await upstreams.stop_connections()
        client_sessions = _client_sessions_holder.get("registry")
        if client_sessions is not None:
            client_sessions.close()
        login_providers = _login_providers_holder.get("providers")
        if login_providers:
            for provider in login_providers:
                try:
                    await provider.aclose()
                except Exception:  # noqa: BLE001 - shutdown must not be blocked by one provider
                    logger.exception("error closing login provider %s", provider.name)


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
    settings: Settings | None = None,
    register_builtin_catalog: bool = True,
    oauth_store: OAuthStore | None = None,
    login_pending_store: LoginPendingStore | None = None,
    user_resolver: UserDirectoryResolver | None = None,
    observability: RbacObservability | None = None,
    users_store: UsersStore | None = None,
    login_providers: Sequence[LoginProvider] | None = None,
    user_directory: UserDirectory | None = None,
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
    auto_login_providers = login_providers is None
    provisional_login_providers = login_providers
    if provisional_login_providers is None:
        provisional_login_providers = build_login_providers(settings, resolver=None)
    validate_login_providers(provisional_login_providers)
    check_login_providers_for_profile(settings, provisional_login_providers)
    login_providers = provisional_login_providers

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
    #
    # Later finding: the gate used to key off ``settings.google_login_enabled``
    # specifically, so a deployment that passes its own ``login_providers``
    # (a custom redirect or form provider, not the built-in Google one) never
    # got a resolver built for it at all — the directory check silently
    # never ran (``handle_login`` skips it when ``user_resolver is None``),
    # and a custom *redirect* provider's callback got a hard 503 on every
    # sign-in instead (``handle_login_callback`` requires one). The gate is
    # keyed off the actually-configured provider set instead: any provider
    # other than the single built-in ``api_key`` one needs a resolver, since
    # 0.5's directory check is this gate's reason to exist, not a property
    # specific to Google. The one case kept exactly as before is "only the
    # built-in api_key form, nothing else" — the 0.4.0 compatibility case
    # above still applies unchanged there.
    dev_tokens_configured = bool({t for t in settings.dev_tokens.split(",") if t.strip()})
    local_users_directory_ready = settings.users_backend == "local" or (
        settings.users_backend == "http" and settings.users_service_url.strip()
    )
    only_builtin_api_key_provider = (
        len(login_providers) == 1 and login_providers[0].name == "api_key"
    )
    directory_resolver: UserDirectoryResolver | None = user_resolver
    resolver_needed = directory_resolver is None and (
        settings.rbac_enabled
        or (len(login_providers) > 0 and not only_builtin_api_key_provider)
        or (only_builtin_api_key_provider and dev_tokens_configured and local_users_directory_ready)
        or (
            local_users_directory_ready and login_providers_want_directory_resolver(login_providers)
        )
    )
    # Built independently of whether a resolver was injected or auto-built
    # above (an embedding process, or a test, may supply its own resolver for
    # login/RBAC while still wanting the catalog's users_* tools wired to the
    # real directory) -- register_catalog needs this whenever RBAC enforces,
    # the resolver-building branch below needs it whenever it runs at all.
    directory: UserDirectory | None = user_directory
    if directory is not None:
        # build_user_directory() already runs this check on the directory it
        # builds; a directory passed in directly (an embedding process, a
        # test, a plugin) gets the same refusal for declaring "admin"
        # without implementing UserDirectoryAdmin.
        directory = validate_directory_capabilities(directory)
    if directory is None and (resolver_needed or settings.rbac_enforcing):
        directory = build_user_directory(settings, users_store=users_store)
    if resolver_needed:
        directory_resolver = build_user_directory_resolver(
            settings,
            directory=directory,
            revision_reader=shared_revision,
        )

    if auto_login_providers:
        login_providers = build_login_providers(settings, resolver=directory_resolver)
        validate_login_providers(login_providers)
        check_login_providers_for_profile(settings, login_providers)

    if (
        api_key_login_configured(settings)
        and directory is not None
        and "api_keys" not in directory.capabilities
    ):
        raise ConfigError(
            "API-key sign-in needs a users directory that stores API keys "
            "(KEYSTONE_MCP_USERS_BACKEND=local). Remove api_key from the login "
            "providers or switch the directory."
        )

    identity_binder = None
    if settings.login_identity_binding == "bind":
        if directory is None or "identity_binding" not in directory.capabilities:
            backend_name = settings.users_backend
            raise ConfigError(
                "KEYSTONE_MCP_LOGIN_IDENTITY_BINDING=bind needs a users directory "
                "with the 'identity_binding' capability; the built-in directory has it, "
                f"{backend_name!r} does not"
            )
        identity_binder = directory

    _login_providers_holder["providers"] = list(login_providers)

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
        RbacPolicyManager(
            settings,
            upstream_catalog_state=lambda: upstreams.catalog_state(),
            extra_catalog_names=lambda: (
                upstreams.content.rbac_names() | upstreams.content.legacy_rbac_names()
            ),
        )
        if settings.rbac_enabled
        else None
    )
    rbac_observability = observability or RbacObservability(
        settings,
        policy_manager=policy_manager,
    )
    if policy_manager is not None:
        policy_manager._on_identity = rbac_observability.record_policy_identity

    if users_store is not None and directory_resolver is not None:
        from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver

        if isinstance(directory_resolver, CachedUserDirectoryResolver):
            directory_resolver.set_observer(rbac_observability)

            def _on_users_change(bump_ok: bool) -> None:
                directory_resolver.invalidate_local()
                if not bump_ok:
                    rbac_observability.record_users_revision_bump_failed()

            users_store.add_change_listener(_on_users_change)

    session_revoker = SessionRevoker(store, pending_store)
    _session_revoker_holder["revoker"] = session_revoker

    oauth = KeystoneOAuthProvider(
        settings,
        store,
        pending_store,
        login_providers=login_providers,
        user_resolver=directory_resolver,
        observability=rbac_observability,
        identity_binder=identity_binder,
    )
    mcp = FastMCP(
        name="keystone-mcp",
        version=keystone_mcp.__version__,
        auth=oauth,
        lifespan=_keystone_lifespan,
    )

    # Tracks open connections (handshake era) and ``subscriptions/listen``
    # streams (2026-07-28 era) so the surface reconciler can notify them of a
    # catalog change, a policy reload or a users-directory change (Y05).
    # Registered on the private low-level server (``FastMCP._mcp_server``,
    # the same field X01 documented as closed API) so the SDK advertises
    # ``tools.listChanged=true`` to 2026-07-28 clients -- FastMCP 4.1 does not
    # serve ``subscriptions/listen`` on its own (test-sentinel:
    # ``test_list_changed_is_advertised_on_both_eras``).
    client_sessions = ClientSessionRegistry()
    mcp._mcp_server.add_request_handler(
        "subscriptions/listen",
        mcp_types.SubscriptionsListenRequestParams,
        client_sessions.listen_handler,
    )
    _client_sessions_holder["registry"] = client_sessions

    # Login page: GET renders the consent screen, POST validates the single
    # configured form-kind provider's credentials and issues the
    # authorization code (no code on failure).
    @mcp.custom_route("/login", methods=["GET"])
    async def _login_get(request):  # noqa: ANN001
        return await oauth.render_login(request)

    @mcp.custom_route("/login", methods=["POST"])
    async def _login_post(request):  # noqa: ANN001
        return await oauth.handle_login(request)

    # One GET/POST/callback trio per configured redirect provider (X03): a
    # provider that is not configured gets no route at all, so a request for
    # it 404s from Starlette's own routing rather than a Keystone error page.
    # The provider named "google" gets exactly the paths it always has
    # (/login/google, /login/google/callback — S4), since _callback_url()
    # builds that address from the name the same way for every provider.
    for _provider in login_providers:
        if _provider.kind != "redirect":
            continue

        def _make_login_redirect_routes(_name: str = _provider.name):
            async def _get(request):  # noqa: ANN001
                return await oauth.start_login_redirect_get(request, _name)

            async def _post(request):  # noqa: ANN001
                return await oauth.start_login_redirect(request, _name)

            async def _callback(request):  # noqa: ANN001
                return await oauth.handle_login_callback(request, _name)

            return _get, _post, _callback

        _login_get_handler, _login_post_handler, _login_callback_handler = (
            _make_login_redirect_routes()
        )
        mcp.custom_route(f"/login/{_provider.name}", methods=["GET"])(_login_get_handler)
        # Consent screen's provider button posts here (CSRF-checked) instead
        # of following a bare link, so the redirect sign-in cannot be
        # triggered from a cross-site page or an emailed URL (A13).
        mcp.custom_route(f"/login/{_provider.name}", methods=["POST"])(_login_post_handler)
        mcp.custom_route(f"/login/{_provider.name}/callback", methods=["GET"])(
            _login_callback_handler
        )

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
        upstream_max_response_bytes=settings.upstream_max_response_bytes,
        upstream_max_schema_bytes=settings.upstream_max_schema_bytes,
        upstream_max_catalog_items=settings.upstream_max_catalog_items,
        schema_patches=load_proxy_schema_patches(settings.proxy_schema_patches_path),
        status_envelope=settings.proxy_status_envelope,
        proxy_elicitation=settings.proxy_elicitation,
        discovery_retries=settings.upstream_discovery_retries,
        refresh_enabled=settings.refresh_interval_seconds > 0,
        identity_issuer=settings.base_url.rstrip("/"),
        _identity_signing_key_pem=settings.identity_signing_key,
    )
    upstreams.observability = rbac_observability
    upstreams.rbac_mode = settings.rbac_mode

    policy_revision_watcher = None
    if policy_manager is not None and settings.redis_url.strip():
        from keystone_mcp.rbac.policy_revision import (
            PolicyRevisionWatcher,
            RedisPolicyRevisionStore,
        )

        redis_client = getattr(store, "redis", None)
        if redis_client is None:
            from keystone_mcp.redis_client import redis_from_url

            redis_client = redis_from_url(settings.redis_url)
        policy_revision_watcher = PolicyRevisionWatcher(
            store=RedisPolicyRevisionStore(
                redis_client,
                key=settings.policy_redis_revision_key,
            ),
            policy_manager=policy_manager,
            registry=registry,
            observability=rbac_observability,
        )

    # Core of changing the RBAC policy through the agent instead of a server
    # login: lets a later release's policy_* tools read and change the policy
    # file with the same validation a hot-reload runs. Built whenever RBAC
    # actually enforces (nothing to administer otherwise) and policy_tools !=
    # "off" (an operator who wants no policy_* tools at all skips this too).
    policy_store: PolicyStore | None = (
        PolicyStore(
            settings=settings,
            policy_manager=policy_manager,
            registry=registry,
            observability=rbac_observability,
            directory=directory,
            revision_watcher=policy_revision_watcher,
        )
        if policy_manager is not None and settings.rbac_enforcing and settings.policy_tools != "off"
        else None
    )
    _policy_store_holder["store"] = policy_store

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
        from keystone_mcp.rbac.loader import delegation_catalog_names
        from keystone_mcp.rbac.management import snapshot_and_file_management_source

        mgmt_source = (
            snapshot_and_file_management_source(policy_manager)
            if policy_manager is not None
            else None
        )
        catalog_names_source = (
            (lambda: delegation_catalog_names(policy_manager, registry))
            if policy_manager is not None
            else None
        )
        register_catalog(
            registry,
            settings,
            observability=rbac_observability,
            directory=directory,
            role_source=policy_role_source(policy_manager),
            management_source=mgmt_source,
            catalog_names_source=catalog_names_source,
            policy_store=policy_store,
            session_revoker=session_revoker,
        )
        _warn_if_admin_tools_are_unguarded(registry, settings)

    _register_default_upstreams(upstreams, settings)

    def _known_name(kind: str, name: str) -> bool:
        if kind == "tool":
            return registry.has_published_name(name)
        if kind == "prompt":
            return upstreams.content.owner_of_published_prompt(name) is not None
        return (
            upstreams.content.owner_of_resource_rbac(name) is not None
            or upstreams.content.owner_of_template_rbac(name) is not None
        )

    rbac_observability.set_known_name_check(_known_name)

    # Remembers a handshake-era connection even for a request that a later
    # middleware throttles or RBAC denies, so added before every other
    # middleware (test-sentinel: test_session_is_tracked_even_when_rbac_denies).
    mcp.add_middleware(SessionTrackingMiddleware(client_sessions))

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
                content_catalog=upstreams.content,
                policy_revision_watcher=policy_revision_watcher,
            )
        )

    from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware

    mcp.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))

    mcp.add_middleware(
        ToolCallObservabilityMiddleware(observability=rbac_observability),
    )

    from keystone_mcp.identity_assertion import IDENTITY_JWKS_PATH, build_identity_jwks

    @mcp.custom_route(IDENTITY_JWKS_PATH, methods=["GET"])
    async def _identity_jwks(_request):  # noqa: ANN001
        from starlette.responses import JSONResponse, Response

        private_key = upstreams._identity_es256_private_key
        if private_key is None:
            return Response(status_code=404)
        return JSONResponse(
            build_identity_jwks(private_key),
            headers={"Cache-Control": "public, max-age=300"},
        )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def _healthz(_request):  # noqa: ANN001
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok"})

    # The HTTP directory's own availability already fails closed on every
    # call that needs it (S16, see ReadinessProbe's module docstring): never
    # poll it from /readyz, whatever object .backend happens to carry (a test
    # double with no .name attribute is left alone, so it keeps exercising
    # whatever ping() behavior it defines).
    _readyz_backend = getattr(directory_resolver, "backend", None)
    if getattr(_readyz_backend, "name", None) == "http":
        _readyz_backend = None
    bootstrap_state = _bootstrap_state_holder.get("state")
    if bootstrap_state is None:
        bootstrap_state = BootstrapState()
    readiness_probe = ReadinessProbe(
        redis=getattr(store, "redis", None),
        policy_manager=policy_manager,
        users_backend=_readyz_backend,
        upstreams=upstreams,
        require_all=settings.upstream_require_all,
        bootstrap_state=bootstrap_state,
    )

    @mcp.custom_route("/readyz", methods=["GET"])
    async def _readyz(request):  # noqa: ANN001
        from starlette.responses import JSONResponse

        report = await readiness_probe.run()
        body: dict[str, object] = {"status": "ok" if report.ready else "degraded"}
        if _is_trusted_internal_caller(request, settings):
            body["checks"] = dict(report.checks)
            body["upstreams"] = upstreams.upstream_readiness_snapshot()
            identity = policy_manager.identity if policy_manager is not None else None
            body["policy_content_hash"] = identity.content_hash if identity is not None else None
            if policy_revision_watcher is not None:
                in_sync = policy_revision_watcher.in_sync
                body["policy_in_sync"] = in_sync
            else:
                body["policy_in_sync"] = None
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
            policy_revision_watcher=policy_revision_watcher,
            client_sessions=client_sessions,
        )
    _reconciler_holder["reconciler"] = reconciler
    _upstreams_holder["upstreams"] = upstreams

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
    if not client_address_allowed(client_host, settings.internal_allowed_cidrs):
        return False
    host_header = request.headers.get("host", "")
    any_port, exact = host_allowlist_sets(effective_allowed_hosts(settings))
    return host_allowed(
        host_header,
        any_port=any_port,
        exact=exact,
        allow_ip_literal=True,
    )


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
            identity_secret_env=cfg.identity_secret_env,
            identity_alg=cfg.identity_alg,
            transport=cfg.transport,
            command=cfg.command,
            args=cfg.args,
            env_from=cfg.env_from,
            cwd=cfg.cwd,
            publish_resources=cfg.publish_resources,
            resource_filter=cfg.build_resource_filter(),
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

    overrides = settings.upstream_tool_timeouts
    if overrides:
        known: set[str] = set()
        for route in upstreams.registry.routes.values():
            if route.mode != "live" or route.namespace is None:
                continue
            known.add(route.published_name)
            known.add(route.upstream_tool or route.name)
        unknown = sorted(key for key in overrides if key not in known)
        if unknown:
            logger.warning(
                "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS keys match no published tool: %s "
                "(an unavailable upstream's tools are not known yet)",
                unknown,
            )

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
    bootstrap_state: BootstrapState | None = None,
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
        if bootstrap_state is not None and bootstrap_state.is_pending():
            logger.info("SIGHUP ignored: startup still in progress")
            return
        if reconciler is not None and reconciler.request_policy_reload():
            return
        _reload_policy_inline()

    signal.signal(signal.SIGHUP, _on_sighup)
    logger.info("rbac policy SIGHUP hot-reload handler installed")


async def _warm_up_one_login_provider(provider: LoginProvider) -> None:
    try:
        await asyncio.wait_for(provider.warm_up(), timeout=5)
    except Exception as exc:  # noqa: BLE001 - logged and intentionally swallowed
        logger.warning("login provider %s is not ready: %s", provider.name, type(exc).__name__)


async def _warm_up_login_providers(login_providers: Sequence[LoginProvider]) -> None:
    """Call ``warm_up()`` on every configured login provider, 5s timeout each.

    Providers are warmed in parallel. A provider that times out or raises does
    not stop the server from starting: sign-in through it will simply fail
    until it recovers, the same way an unreachable upstream does not block
    startup elsewhere in this module.
    """
    if not login_providers:
        return
    await asyncio.gather(*(_warm_up_one_login_provider(p) for p in login_providers))


def _enforce_discovery_outcome(
    settings: Settings,
    discovery: UpstreamDiscoveryResult,
) -> None:
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


async def _bootstrap_after_users_store(
    upstreams: UpstreamRegistry,
    registry: RouterRegistry,
    settings: Settings,
    policy_manager: RbacPolicyManager | None,
    *,
    observability: RbacObservability | None = None,
    login_providers: Sequence[LoginProvider] | None = None,
) -> UpstreamDiscoveryResult:
    if login_providers:
        await _warm_up_login_providers(login_providers)
    discovery = await bootstrap_upstreams(upstreams, settings)
    _enforce_discovery_outcome(settings, discovery)
    bootstrap_rbac_policy(
        policy_manager,
        registry,
        discovery=discovery,
        observability=observability,
    )
    return discovery


async def run_deferred_bootstrap(
    upstreams: UpstreamRegistry,
    registry: RouterRegistry,
    settings: Settings,
    policy_manager: RbacPolicyManager | None,
    *,
    observability: RbacObservability | None = None,
    login_providers: Sequence[LoginProvider] | None = None,
    reconciler: SurfaceReconciler | None = None,
    state: BootstrapState,
) -> None:
    """Warm up login providers, start stdio connections, discover upstreams, load policy."""
    try:
        if login_providers:
            await _warm_up_login_providers(login_providers)
        await upstreams.start_connections()
        discovery = await bootstrap_upstreams(upstreams, settings)
        _enforce_discovery_outcome(settings, discovery)
        bootstrap_rbac_policy(
            policy_manager,
            registry,
            discovery=discovery,
            observability=observability,
        )
        if reconciler is not None:
            await reconciler.start()
        state.mark_ready()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("startup refused: %s", exc)
        state.mark_failed(str(exc))
        _startup_failure_holder["error"] = exc
        _request_shutdown()


async def bootstrap_platform(
    upstreams: UpstreamRegistry,
    registry: RouterRegistry,
    settings: Settings,
    policy_manager: RbacPolicyManager | None,
    *,
    observability: RbacObservability | None = None,
    users_store: UsersStore | None = None,
    login_providers: Sequence[LoginProvider] | None = None,
) -> UpstreamDiscoveryResult:
    """Migrate/seed the users directory, warm up login providers, discover upstreams, load RBAC policy."""
    if users_store is not None:
        await bootstrap_users_store(users_store, settings)
    return await _bootstrap_after_users_store(
        upstreams,
        registry,
        settings,
        policy_manager,
        observability=observability,
        login_providers=login_providers,
    )


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

    internal_paths: tuple[str, ...] = ()
    internal_prefixes: tuple[str, ...] = ()
    if settings.metrics_enabled:
        metrics_path = settings.metrics_path.strip() or "/metrics"
        internal_paths = (metrics_path,)
    if settings.internal_endpoints_enabled:
        internal_prefixes = ("/internal/",)

    stack: list = [
        Middleware(
            HostGuardMiddleware,
            allowed_hosts=effective_allowed_hosts(settings),
            internal_paths=internal_paths,
            internal_prefixes=internal_prefixes,
        )
    ]
    if settings.log_access_enabled:
        stack.append(Middleware(AccessLogMiddleware, settings=settings))
    return stack


def main() -> None:
    try:
        env_result = load_env_file()
        settings = load_settings()
    except ConfigError as exc:
        # No logging configuration exists yet at this point (configure_logging
        # runs right after), so an uncaught ConfigError would otherwise print a
        # full Python traceback; a misconfigured .env or environment variable
        # is an operator mistake, not a bug, and deserves a one-line message.
        for problem in exc.problems:
            print(f"keystone-mcp: {problem}", file=sys.stderr)
        raise SystemExit(1) from exc
    configure_logging(settings)
    try:
        _ = settings.upstreams
    except ValueError as exc:
        logger.error("startup refused: %s", f"upstream registry: {exc}")
        raise SystemExit(1) from exc
    try:
        preflight_rbac_policy_file(settings)
    except PolicyLoadError as exc:
        logger.error("startup refused: %s", exc)
        raise SystemExit(1) from exc
    logger.info("deployment profile: %s", settings.deployment_profile)
    for warning in startup_warnings(settings):
        logger.warning(warning)
    if env_result.path is not None:
        logger.info("loaded %d settings from %s", len(env_result.loaded), env_result.path)
    if env_result.ignored_forwarded_allow_ips:
        logger.warning(
            "FORWARDED_ALLOW_IPS in %s is ignored: it is read by uvicorn from the "
            "process environment, not from .env; set it in the service environment "
            "(systemd Environment=, docker -e, Kubernetes env)",
            env_result.path,
        )
    if not settings.oauth_dcr_enabled:
        logger.info(
            "dynamic client registration is disabled; register OAuth clients "
            "manually (docs/environment.md#registering-a-client-manually)"
        )
    bootstrap_state = BootstrapState(deferred=True)
    _bootstrap_state_holder["state"] = bootstrap_state
    try:
        mcp, registry, _oauth, upstreams, policy_manager, observability, reconciler = build_server(
            settings=settings,
        )
    except (ConfigError, UsersConfigError) as exc:
        logger.error("startup refused: %s", exc)
        raise SystemExit(1) from exc

    users_store = _users_store_holder["store"]
    login_providers = _login_providers_holder["providers"]
    try:
        if users_store is not None:
            asyncio.run(bootstrap_users_store(users_store, settings))
    except UsersBootstrapError as exc:
        logger.error("startup refused: %s", exc)
        raise SystemExit(1) from exc

    async def _deferred_bootstrap() -> None:
        await run_deferred_bootstrap(
            upstreams,
            registry,
            settings,
            policy_manager,
            observability=observability,
            login_providers=login_providers,
            reconciler=reconciler,
            state=bootstrap_state,
        )

    _deferred_bootstrap_holder["factory"] = _deferred_bootstrap

    install_policy_reload_signal(
        registry,
        policy_manager,
        observability=observability,
        reconciler=reconciler,
        bootstrap_state=bootstrap_state,
    )
    mcp.run(
        transport="http",
        host=settings.host,
        port=settings.port,
        path=settings.http_path,
        middleware=_http_asgi_middleware(settings) or None,
        show_banner=False,
        uvicorn_config={
            "access_log": False,
            "log_config": None,
            "timeout_graceful_shutdown": settings.shutdown_grace_seconds,
        },
    )
    if _startup_failure_holder["error"] is not None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
