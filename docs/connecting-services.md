# Connecting an upstream service to Keystone-MCP

Operating guide: [facade.md](facade.md). This page is the contract the service meets.

Generic contract for any service you want Keystone-MCP to proxy as a namespace
of tools. There is no framework requirement on the upstream side beyond
speaking MCP over Streamable HTTP; this document describes the shape that
makes discovery, health-checking and identity propagation work smoothly. A
working minimal service that meets this contract is
[`../examples/hello-upstream/`](../examples/hello-upstream/).

## Contract

**Serve MCP over Streamable HTTP on `/mcp`, expose `/healthz`, and honour
`X-Author-Email` on every call.** Keystone-MCP discovers the service's tool catalog at startup and then on a
live refresh timer (`list_tools()`), re-publishing each tool as
`<namespace>_<tool>`.

```
Claude Desktop / Cursor
   │  OAuth
   ▼
Keystone-MCP (public)
   │  McpProxyAdapter, X-Author-Email
   ▼
mysvc-mcp (internal, mcp-upstreams network)   /mcp, /healthz
```

## Requirements

1. Serve Streamable HTTP MCP on `/mcp`.
2. Expose `/healthz` for container health checks (a plain HTTP endpoint, not an
   MCP method).
3. Use a stable DNS name on the shared Docker network that the registry
   entry can reach, e.g. `mysvc-mcp`.
4. Read `X-Author-Email` from every incoming call if the service needs to know
   who is acting — Keystone-MCP has already verified this identity; the
   upstream should trust it only over a private network it controls.
5. Never expose the MCP port on a public interface; only Keystone-MCP (and
   whatever else legitimately needs direct access) should reach it.
6. Choose a tool-name prefix convention that plays well with namespace
   mounting: a flat `list_tools()` response is fine, but if the service
   publishes several logical groups of tools, a consistent prefix per group
   (e.g. `billing_*`, `reports_*`) lets Keystone-MCP split them into separate
   namespaces — see [adding-routes.md](adding-routes.md#multi-mounting-one-upstream-under-several-namespaces).
7. Answer with whatever shape your tool naturally returns — plain text,
   several content blocks, images, embedded resources, or structured JSON.
   Keystone-MCP forwards the response as-is by default; a JSON dict with a
   `status` field is not required.
8. Required and optional parameters may come in any order in `inputSchema`,
   and property names need not be valid Python identifiers (`max-results`,
   `from`): Keystone-MCP publishes the schema as-is and leaves argument
   validation to your service.

## Authenticating Keystone-MCP to your service

By default Keystone-MCP proves nothing about itself beyond `X-Author-Email`,
and anything on the same network can send that same header and impersonate
any user. A registry entry's optional `auth.bearer_env` closes that gap:

```yaml
entries:
  - name: docs-mcp
    url: https://docs-mcp.internal.example/mcp
    namespace: docs
    auth:
      bearer_env: KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN
```

`bearer_env` names an environment variable holding the token's value; it is
not read from this file. The name must start with the reserved
`KEYSTONE_MCP_UPSTREAM_` prefix (e.g. `KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN`) and
must not be one of the handful of `KEYSTONE_MCP_UPSTREAM_*` variables
Keystone-MCP itself already reads as settings (`KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP`
and similar — see [environment.md](environment.md#upstreams)); registry
validation refuses the entry otherwise. This closes a gap where an entry
could otherwise name any environment variable at all — e.g.
`bearer_env: KEYSTONE_MCP_GOOGLE_CLIENT_SECRET` next to a `url` the deployer
controls — and have Keystone-MCP send that secret to the entry's upstream as
a bearer token. Keystone-MCP reads the named variable once at startup and
sends `Authorization: Bearer <value>` on every discovery (`list_tools`) and
proxied call to that upstream — if the variable is unset or empty,
Keystone-MCP refuses to start. Your service should check that header
**first**, and only then trust `X-Author-Email` on the same request;
`X-Author-Email` alone is not proof the call came from Keystone-MCP.

Rotating the token means setting a new value for the environment variable and
restarting the Keystone-MCP process; there is no live-reload for it. Over
`http` (allowed only on a private network, see
[`KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP`](environment.md)) the token
travels in clear text, same as every other header; prefer `https` whenever the
upstream is reachable over anything less trusted than a network Keystone-MCP
alone controls.

## Tool naming

Client-visible tool names are `<namespace>_<upstream tool name>` (or the name
with `strip_prefix` removed, when configured). Pick upstream tool names that
read sensibly once namespace-prefixed and, ideally, do not already start with
a word that duplicates the namespace (`mysvc_mysvc_search` is legal but odd).

### Choosing a namespace

A registry entry's `namespace` is validated at load time (startup and
`keystone-mcp upstream validate`):

- **Characters.** 1–64 characters of `A-Z`, `a-z`, `0-9`, `_` or `-`, not
  starting or ending with `_` or `-`. No glob characters (`*`, `?`, `[`) — an
  RBAC policy pattern's "namespace" head is taken literally (see
  [rbac-policy-format.md](rbac-policy-format.md)).
- **No collision with a built-in tool.** A namespace is rejected if
  `<namespace>_` is the start of any built-in tool name — this rules out
  `users`, `create`, `create_upload`, `get` and `get_download`.
- **No collision between namespaces.** Two namespaces `A` and `B` cannot be
  configured together if `B` starts with `A + "_"` (e.g. `billing` and
  `billing_admin`): upstream `A` publishing a tool `x_y` would publish the
  same name as upstream `B` publishing tool `y`. Rename one of them;
  `billing` and `billingadmin` (no underscore boundary) are fine together.

## Docker network example

```yaml
services:
  mysvc-mcp:
    build: ./mysvc
    environment:
      MYSVC_MCP_TRANSPORT: http
      MYSVC_MCP_HOST: 0.0.0.0
      MYSVC_MCP_PORT: 8081
    networks:
      - mcp-upstreams
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz')"]

  keystone-mcp:
    image: ghcr.io/keystone-codes/keystone-mcp:0.4.0
    environment:
      KEYSTONE_MCP_UPSTREAMS_PATH: /etc/keystone-mcp/upstreams.yaml
      # Plain http is fine on this internal Docker network, which is not
      # reachable from the internet; the production profile logs one
      # warning at startup.
      KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP: "true"
    volumes:
      - ./upstreams.yaml:/etc/keystone-mcp/upstreams.yaml:ro
    networks:
      - mcp-upstreams
    ports:
      - "127.0.0.1:8080:8080"

networks:
  mcp-upstreams:
    driver: bridge
```

`upstreams.yaml`, next to the compose file:

```yaml
schema_version: 1
entries:
  - name: mysvc
    url: http://mysvc-mcp:8081/mcp
    namespace: mysvc
    enabled: true
```

Keep the upstream's own storage (database, object store, vendor APIs) on a
separate, private network; Keystone-MCP and the upstream's MCP facade only need
to share `mcp-upstreams`.

## Checklist

1. `/mcp` speaks Streamable HTTP MCP; `/healthz` returns 200 when ready.
2. Service is reachable from Keystone-MCP's container on the shared network
   under a stable DNS name.
3. Registry entry added; `keystone-mcp upstream validate --path upstreams.yaml`
   passes.
4. Start order does not matter: a service that is down is retried on every
   refresh.
5. Smoke test: `list_tools` on Keystone-MCP shows the expected
   `<namespace>_*` tools, and one read-only call succeeds end-to-end.

See [adding-routes.md](adding-routes.md) for the router-side configuration
(filters, multi-mounting, timeouts, schema patches) once the upstream meets
this contract.
