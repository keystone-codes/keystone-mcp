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

Keys must name the **published** tool (what the client calls). The upstream's
own tool name still works as a key but is deprecated since 0.6.0 — Keystone logs
a warning naming the published key to use instead. Keys that match no discovered
tool are listed in a startup warning after discovery (unavailable upstreams may
not be known yet).

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
`src/keystone_mcp/adapters/base.py`: `Pattern.SYNC` (default),
`Pattern.CONTINUATION` — it only selects the stub answer while the route is in
stub mode). A route is registered with
`RouterRegistry.add_route(name, target, ...)`, which builds the MCP tool
signature from a list of `Param` objects and publishes it on the FastMCP
instance — see `src/keystone_mcp/catalog/builtin.py` for the routes the
platform registers by default: the `users_*` admin tools (only when
`KEYSTONE_MCP_RBAC_MODE=enforce`).

`src/keystone_mcp/adapters/` ships `stub.StubAdapter` — canonical stub
response by pattern, the default target for a route registered before its
real adapter exists. Reference adapters for forks (`WebhookAdapter`,
`ExternalHttpAdapter`) live in `keystone_mcp.contrib.adapters`: see
[contrib/adapters.md](contrib/adapters.md). Neither is registered by default
or covered by [compatibility.md](compatibility.md); a fork that wants one registers a
route with it as `target`.

To use one, register a route with `mode="stub"` while the target is being
built, and flip it with `registry.set_mode(name, "live")` once ready — nothing
about the transport, identity propagation, or `task_id` computation changes
between the two modes.

## Extending Keystone-MCP in a fork

A team that forks Keystone-MCP to front its own agentic application can
already swap several of these seams for its own code, each described below.
Sign-in providers and users directories are packages discovered through entry
points; see [plugins.md](plugins.md).

### Replaceable today

#### Sign-in: `LoginProvider`

Sign-in providers implement `keystone_mcp.login.LoginProvider` and are
discovered through the `keystone_mcp.login_providers` entry point. Google,
generic OpenID Connect, and the API-key form ship that way. A fork adds a
provider type by publishing a package. See
[login-providers.md](login-providers.md) and [plugins.md](plugins.md).
`IdentityProvider` and `build_server(identity_provider=...)` were removed in
0.5.0.

#### Users directory: `UserDirectory`

Reading and administering people is one protocol,
`keystone_mcp.user_directory.UserDirectory` (plus the optional
`UserDirectoryAdmin` capability) — not something you wire by editing a core
factory function. Writing your own directory (a dict, a YAML file, LDAP, a
different internal service), the protocol's rules, the HTTP contract the
built-in `KEYSTONE_MCP_USERS_BACKEND=http` directory speaks, and how
`users_*` tool publication depends on what a directory declares: see
[user-directory.md](user-directory.md). Registering a directory from your own
package without editing core code is done through a Python entry point; see
[plugins.md](plugins.md).

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

Custom built-in tools (`Adapter` and `RouterRegistry.add_route`) are still
registered in the fork's own code. Sign-in providers and users directories
are entry points, and a fork can run the contract tests against its own
implementation (`pytest -p keystone_mcp.contract_tests`) before deploying it.
See [plugins.md](plugins.md).
