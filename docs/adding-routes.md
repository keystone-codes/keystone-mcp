# Adding routes to Keystone-MCP

Operating guide: [facade.md](facade.md). This page is the router-side detail.

The primary way to publish tools through Keystone-MCP is to connect a whole
upstream MCP server, not to hand-write individual routes. This document covers
that path first, then the lower-level `Adapter` protocol for the rarer case of
a custom, built-in route.

## Connecting an upstream MCP server

Add an entry to the upstream registry file (`KEYSTONE_MCP_UPSTREAMS_PATH`;
format: `src/keystone_mcp/upstream_registry/load.py`, `parse_upstream_entries`):

```yaml
schema_version: 1
entries:
  - name: mysvc
    url: http://mysvc-mcp:8081/mcp
    namespace: mysvc
    enabled: true
```

At startup, `bootstrap_upstreams` calls `list_tools()` on each enabled upstream
and registers one live proxy route per discovered tool, mounted under a FastMCP
sub-server named after `namespace`. The client sees each tool as
`<namespace>_<tool>` (FastMCP's mount-prefixing), e.g. `mysvc_search_widgets`.
Each proxied call goes through `McpProxyAdapter`, which forwards the verified
identity as `X-Author-Email` and applies the tool's configured timeout.

### Filtering which tools are discovered

Two optional fields narrow which of the upstream's tools are registered:

```yaml
- name: mysvc
  url: http://mysvc-mcp:8081/mcp
  namespace: mysvc
  include_prefixes: ["public_"]
  exclude_prefixes: ["public_internal_"]
```

`include_prefixes` keeps only tools whose upstream name starts with one of the
listed prefixes; `exclude_prefixes` drops tools whose name starts with one of
its prefixes (checked after `include_prefixes`). Both accept a single string or
a list of strings.

### Multi-mounting one upstream under several namespaces

A single upstream MCP server that publishes several logical tool families can
be registered more than once, each entry pointing at the same `url` but a
different `namespace` and a different `strip_prefix`:

```yaml
schema_version: 1
entries:
  - name: mysvc
    url: http://mysvc-mcp:8081/mcp
    namespace: mysvc
    exclude_prefixes: ["billing_", "reports_"]
  - name: mysvc-billing
    url: http://mysvc-mcp:8081/mcp
    namespace: billing
    include_prefixes: ["billing_"]
    strip_prefix: "billing_"
  - name: mysvc-reports
    url: http://mysvc-mcp:8081/mcp
    namespace: reports
    include_prefixes: ["reports_"]
    strip_prefix: "reports_"
```

`strip_prefix` removes the given prefix from the upstream tool name before it
is registered under the namespace, so `billing_list_invoices` becomes the
published tool `billing_list_invoices` (namespace `billing` + the stripped name
`list_invoices`) rather than `billing_billing_list_invoices`. `strip_prefix`
must align with `include_prefixes` (share a common prefix), or the entry is
rejected at startup. Exclude the split-out prefixes from the primary entry so
the same tool is not registered twice.

### Per-tool timeout overrides

`KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS` sets the default wait for every
proxied call. `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` overrides it per published
tool name:

```json
{"mysvc_bulk_export": 60, "mysvc_ping": 5}
```

### Patching a thin upstream schema

If an upstream's advertised `inputSchema` lags its actual runtime (a common gap
when a published image trails deployed code), `KEYSTONE_MCP_PROXY_SCHEMA_PATCHES`
names a JSON file that merges extra properties into specific tools' schemas
without waiting on the upstream to catch up. The file format — keyed by
namespace, then upstream tool name, then property name — is documented in
`src/keystone_mcp/router/proxy_schema.py` and applied by
`McpProxyAdapter`/`UpstreamRegistry` at discovery time; a patch for a tool the
upstream does not expose is simply never applied. The patched
property is published to clients verbatim — the full JSON Schema fragment
(`enum`, bounds, nested objects, not just a type), not a thinned-down
reconstruction of it.

### RBAC policy rows for a new upstream

Every published tool name (namespace prefix included) needs a role that can
reach it or it is unreachable once RBAC is `enforce`. For the multi-mount
example above, a role's `allow` list would need entries like:

```yaml
roles:
  billing_viewer:
    allow:
      - billing_list_invoices
      - billing_get_invoice
```

See [rbac-policy-format.md](rbac-policy-format.md) for the full policy file
format, and [examples/rbac-policy.full-example.yaml](../examples/rbac-policy.full-example.yaml)
for a worked example with fictional tool names.

## Custom adapters (advanced)

Every route is dispatched through the `Adapter` protocol
(`src/keystone_mcp/adapters/base.py`):

```python
class Adapter(Protocol):
    async def execute(
        self,
        route: Route,
        ctx: RouteContext,
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any]: ...
```

`ctx` carries the verified identity, the deterministic `task_id`, the resolved
`Settings`, and the route's response `pattern` (`Pattern` in
`src/keystone_mcp/adapters/base.py`). A route is registered with
`RouterRegistry.add_route(name, target, ...)`, which builds the MCP tool
signature from a list of `Param` objects and publishes it on the FastMCP
instance — see `src/keystone_mcp/catalog/builtin.py` for the routes the
platform registers by default: `create_upload_url` and `get_download_link`
(only when `KEYSTONE_MCP_FILE_API_URL` is set), and the `users_*` admin tools
(only when `KEYSTONE_MCP_RBAC_MODE=enforce`).

`src/keystone_mcp/adapters/` also ships several **reference adapters that are
not registered by default** — useful as a starting point for a deployment that
needs a built-in route beyond upstream proxying, but inert until something
calls `registry.add_route` with one of them as `target`:

| Adapter | Purpose |
|---|---|
| `webhook.WebhookAdapter` | Submit to an async webhook endpoint, then long-poll a task-result endpoint for completion. |
| `external_http.ExternalHttpAdapter` | Call an arbitrary external HTTP API, with the transform selecting the method (GET/POST) and payload. |
| `det_internal.DetInternalAdapter` | Placeholder for a synchronous internal deterministic-call API; returns a canonical stub until wired to a real target. |
| `chat_attachment.ChatAttachmentAdapter` | Signal outbound file delivery correlated by an external session watcher; keystone-mcp itself is session-blind. |
| `stub.StubAdapter` | Canonical stub response by pattern — the default target for a route registered before its real adapter exists. |

To use one, register a route with `mode="stub"` while the target is being
built, and flip it with `registry.set_mode(name, "live")` once ready — nothing
about the transport, identity propagation, or `task_id` computation changes
between the two modes.

## Extending Keystone-MCP in a fork

A team that forks Keystone-MCP to front its own agentic application can
already swap several of these seams for its own code, each described below
with the file it edits. A few others still need a core change; 0.5.0 plans to
turn those into the same kind of pluggable interface.

### Replaceable today

#### Sign-in secret check: `IdentityProvider`

`IdentityProvider` (`src/keystone_mcp/auth/identity_provider.py`) checks the
credential a client presents when it signs in with a DEV token or an API key
— the api-key page, not the Google button — and binds the asserted email to
the issued access token when the check passes. It is one `runtime_checkable`
protocol with one method:

```python
@runtime_checkable
class IdentityProvider(Protocol):
    async def verify(self, api_token: str, email: str) -> bool: ...
```

Google sign-in never calls this protocol: it goes through
`KeystoneOAuthProvider` and `GoogleOidcClient`
(`src/keystone_mcp/auth/keystone_oauth_provider.py`,
`src/keystone_mcp/auth/google_oidc.py`) instead.

The shipped implementations are `StaticIdentityProvider` (a fixed set of DEV
tokens) and `AuthServiceIdentityProvider` (deprecated HTTP introspection
against `KEYSTONE_MCP_AUTH_SERVICE_*`, removed in 0.4.1). A fork checking its
own credential store writes a class with the same method, for example:

```python
class MyKeyStoreIdentityProvider:
    """Looks up api_token in our own table and compares its bound email."""

    def __init__(self, pool: "asyncpg.Pool") -> None:
        self._pool = pool

    async def verify(self, api_token: str, email: str) -> bool:
        if not api_token or not email or "@" not in email:
            return False
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT email FROM api_keys WHERE token = $1 AND revoked_at IS NULL",
                api_token,
            )
        return row is not None and row["email"].strip().lower() == email.strip().lower()
```

To wire it in, edit `build_identity_provider` in `src/keystone_mcp/server.py`
and return the new class instead of (or alongside) the built-in branches —
honestly, there is no registration point that avoids touching this one
function yet.

#### Users directory: `UserDirectoryBackend`

`UserDirectoryBackend` (`src/keystone_mcp/user_directory/protocol.py`) is the
other `runtime_checkable` protocol, with two methods:

```python
@runtime_checkable
class UserDirectoryBackend(Protocol):
    async def resolve_user(self, email: str) -> UserResolveResult: ...
    async def aclose(self) -> None: ...
```

`UserResolveResult` (`src/keystone_mcp/user_directory/models.py`) carries
`exists`, `roles`, `is_blocked` (plus cache bookkeeping the backend does not
set). The default, `KEYSTONE_MCP_USERS_BACKEND=local`, is
`LocalUserDirectoryBackend` (`src/keystone_mcp/user_directory/local.py`) over
the built-in SQLite/PostgreSQL store. `KEYSTONE_MCP_USERS_BACKEND=http` is
`HttpUserDirectoryBackend` (`src/keystone_mcp/user_directory/http.py`), which
calls `GET /v1/users/resolve?email=…` on an external service — the contract a
fork implements when its people already live somewhere else; see
[below](#the-http-users-directory-contract).

A third kind of backend (LDAP, a different internal service, anything else
that can answer "does this email exist, what are its roles, is it blocked")
implements the same two methods and is selected in
`build_user_directory_resolver`
(`src/keystone_mcp/user_directory/factory.py`), which today only branches on
`local`/`http`; a fork adds a third branch there, or passes its instance
through that function's own `backend=` parameter instead of going through the
`local`/`http` selection at all. Either way, the caching, the Redis-backed
revision marker, and the circuit breaker
(`src/keystone_mcp/user_directory/resolver.py`,
`CachedUserDirectoryResolver`) wrap *any* backend unchanged — a fork's
implementation only has to answer `resolve_user` correctly, not implement its
own cache or failure handling.

#### Built-in tools: `Adapter` and `RouterRegistry.add_route`

See [Custom adapters](#custom-adapters-advanced) above. Use it for a platform
primitive; business logic belongs in an upstream service.

#### Access rules: the policy file

Roles and the tool patterns they may call are data, not code — see
[rbac-policy-format.md](rbac-policy-format.md) for the file format. A fork
ships its own policy file (`KEYSTONE_MCP_RBAC_POLICY_PATH`) and keeps its own
contract tests for that file in its own repository; Keystone-MCP's tests only
cover the loader and the shipped example, never a deployment's actual roles.

#### Upstream schemas: `KEYSTONE_MCP_PROXY_SCHEMA_PATCHES`

Needed when an upstream advertises an `inputSchema` that lags its real
runtime (commonly a published image trailing deployed code). See
[Patching a thin upstream schema](#patching-a-thin-upstream-schema) above for
the file format and `src/keystone_mcp/router/proxy_schema.py` for the loader
a fork can call directly (`load_proxy_schema_patches`) to validate its own
patch file before deploying it.

#### Upstream authentication: `auth.bearer_env`

A registry entry's optional `auth` field
(`src/keystone_mcp/upstream_registry/load.py`,
`src/keystone_mcp/upstream_registry/validate.py`) names an environment
variable holding a bearer token Keystone-MCP sends to that one upstream on
every discovery and proxied call, so the upstream can tell a genuine
Keystone-MCP request from anything else on the same network. See
[Authenticating Keystone-MCP to your service](connecting-services.md#authenticating-keystone-mcp-to-your-service)
for the field and the header it produces.

### The HTTP users directory contract

With `KEYSTONE_MCP_USERS_BACKEND=http`, Keystone-MCP calls the external
service with `Authorization: Bearer <KEYSTONE_MCP_USERS_SERVICE_TOKEN>`; every
email in a path or a query parameter is lower-cased first; every
administration call additionally carries `X-Actor-Email` set to the verified
email of the signed-in administrator, and the service is responsible for
checking that this actor is itself allowed to manage users. After any
mutation, the service must increment the integer at
`KEYSTONE_MCP_USERS_REDIS_REVISION_KEY` (default `km:users:revision`) in the
same Redis Keystone-MCP uses — otherwise Keystone-MCP keeps serving a cached,
stale resolution for up to `KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS`
(default 60) seconds.

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/v1/users/resolve?email=` | — | `{"exists": bool, "roles": [...], "is_blocked": bool}` |
| `GET` | `/v1/users?is_blocked=&role=&email_contains=` | — | `{"users": [...], "total": N}` |
| `POST` | `/v1/users` | `{"email", "full_name", "roles": [...], "created_by", "note"?}` | user object |
| `PATCH` | `/v1/users/{email}` | `{"full_name"?, "note"?}` | user object |
| `POST` | `/v1/users/{email}/block` | — | user object |
| `POST` | `/v1/users/{email}/unblock` | — | user object |
| `PUT` | `/v1/users/{email}/roles` | `{"roles": [...]}` | user object |
| `POST` | `/v1/users/{email}/roles/{role}` | — | user object (grant) |
| `DELETE` | `/v1/users/{email}/roles/{role}` | — | user object (revoke) |

(Endpoints and bodies: `src/keystone_mcp/adapters/users_admin.py`; email path
segments are percent-encoded.)

The administration endpoints' error responses are translated to the `users_*`
tool error codes an agent sees — the same codes the built-in directory
returns, so a fork's HTTP service should raise the matching one rather than
inventing its own:

| Code | Meaning |
|---|---|
| `user_not_found` | No such email. |
| `conflict` | The account, or the role being granted, already exists. |
| `validation_error` | A required argument is missing, or the role is unknown. |
| `last_administrator` | The change would leave no active administrator. |
| `self_admin_mutation_forbidden` | An administrator tried to remove their own `administrator` role. |
| `forbidden` | The actor named in `X-Actor-Email` may not manage users. |
| `service_unconfigured` | `KEYSTONE_MCP_USERS_SERVICE_URL` or the token is empty. |
| `service_timeout` | The request to the service timed out. |
| `service_unavailable` | The service did not answer. |

See [users.md](users.md#errors) for the same table against the built-in
directory.

### Not replaceable yet

- **Google is the only interactive login.** Sign-in through another OIDC
  provider (Okta, Entra, Keycloak) needs a core change today — there is no
  second `KeystoneOAuthProvider` seam a fork can point elsewhere. Planned for
  0.5.0 as a common `LoginProvider` protocol, with Google becoming one
  implementation among several.
- **"Interactive human" is a string comparison.** Whether a signed-in
  identity counts as an interactive human, for `requires_human_identity` in
  the policy file, is `claims.get("auth_method") == "google"`
  (`src/keystone_mcp/rbac/human_identity.py`). A different interactive login
  cannot make this true without a core change. Planned for 0.5.0: the login
  provider itself reports whether its sign-in is interactive.
- **`users_*` knows exactly two directory shapes.** `UsersAdminAdapter`
  (`src/keystone_mcp/adapters/users_admin.py`) dispatches to the built-in
  store or to the HTTP contract above — nothing else. A fork with a third
  kind of directory (LDAP, a different internal service) that also needs
  administration through `users_*`, not just read access through
  `UserDirectoryBackend`, has to edit this adapter. Planned for 0.5.0: one
  `UserDirectory` protocol covering both read and administration, so any
  backend gets both for free.
- **No entry points yet.** Every seam above is wired by editing one factory
  function in the core (`build_identity_provider`,
  `build_user_directory_resolver`, `UsersAdminAdapter`) rather than by
  registering a package. Planned for 0.5.0, alongside publishing
  `keystone-mcp` on PyPI: `keystone_mcp.login_providers` and
  `keystone_mcp.user_directories` entry points a fork's own package declares,
  plus contract tests it can run against its implementation before deploying
  it.
