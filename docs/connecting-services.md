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
live refresh timer (`list_tools()` and, when the service advertises prompts,
`list_prompts()`), re-publishing each tool and prompt as
`<namespace>_<tool>` / `<namespace>_<prompt>`. Resource URIs and URI templates
need a `scheme://` prefix; anything else is not published.

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
4. Verify `X-Keystone-Identity` on every tool call (examples below).
   `X-Author-Email` is unsigned and deprecated.
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

## Subject headers (every proxied call)

| Header | When present | Meaning |
| --- | --- | --- |
| `X-Keystone-Subject` | Always | Verified subject: an email for people, `svc:<name>` for service accounts. |
| `X-Keystone-Subject-Type` | Always | `human` or `service`. |
| `X-Author-Email` | People only | Same email as `X-Keystone-Subject` for humans; omitted for service accounts. Deprecated since 0.5.0, removed in 2.0. |

These headers are trustworthy only if the upstream accepts traffic from
Keystone alone; signed identity (`X-Keystone-Identity`, below) is the
stronger check when configured.

## Who is calling: X-Keystone-Identity

`X-Author-Email` is unsigned: anything on the same network can send that
header and impersonate any user, and it carries no roles. **Deprecated since
0.5.0** (kept until the next major version) — verify `X-Keystone-Identity`
instead.

A registry entry's optional `auth.identity_secret_env` makes Keystone-MCP
sign a short-lived JSON Web Token on every proxied call and send it as
`X-Keystone-Identity`. It is signed `HS256` with a secret unique to this
upstream (the environment variable named by `auth.identity_secret_env`, read
once at startup, never written to the registry file) — compromising one
upstream's secret never lets it forge an assertion for another. Discovery
(`list_tools`) never carries it: there is no human behind that call.

```yaml
entries:
  - name: docs-mcp
    url: https://docs-mcp.internal.example/mcp
    namespace: docs
    auth:
      identity_secret_env: KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET
```

| Claim | Meaning |
|---|---|
| `iss` | Keystone-MCP's own base URL, no trailing slash |
| `aud` | this registry entry's `name` (`docs-mcp` above, not `docs`) |
| `sub` | the calling subject: a person's verified email, lower-cased |
| `sub_type` | `"human"` or `"service"` |
| `email` | present only when `sub_type` is `"human"` |
| `roles` | the roles RBAC evaluated this call against, sorted; `[]` when RBAC is off |
| `rbac` | the RBAC mode Keystone-MCP ran this call under: `"enforce"`, `"observe"` or `"off"` |
| `auth_method` | how the caller signed in (e.g. `"google"`, `"api_key"`), or `"unknown"` |
| `interactive` | whether an interactive human login is bound to the call |
| `client_id` | the caller's OAuth client id, when the token carries one |
| `task_id` | Keystone-MCP's deterministic task id for this call |
| `mcp_method` | `"tools/call"` |
| `mcp_target` | the tool name on *your* side (before namespace prefixing) |
| `iat` / `exp` | issued-at and expiry (Unix seconds); `exp` always covers at least this call's own timeout, plus a 60-second margin |
| `jti` | a random id, for services that want to reject a replayed token |

The JWT header is `{"alg": "HS256", "typ": "keystone-identity+jwt"}`. Verify
the signature with your `auth.identity_secret_env` secret, check `aud`
against your own entry name, and treat the whole header as untrusted
otherwise — verification examples: see below. An entry with no
`auth.identity_secret_env` only ever sends the unsigned, deprecated
`X-Author-Email`; the `production` deployment profile logs a startup warning
for each such entry.

### Verifying the identity assertion

Checking the header costs five lines, in any language that has a JWT
library. What to check:

- **Signature** — HS256, with the exact secret your `auth.identity_secret_env`
  variable holds. Never read the algorithm from the token itself (classic
  "`alg: none`" / algorithm-confusion attack) — pin `["HS256"]` on the
  verify call, the way both reference verifiers below do.
- **`aud`** — must equal this registry entry's own `name` (not its
  `namespace`). An assertion signed for a different upstream, even with the
  same secret by mistake, must be rejected here.
- **`exp`** — with a small clock-skew allowance (30 seconds is what both
  reference verifiers below use); it already covers this call's own timeout
  plus a margin, so a token that has expired really is stale.
- **`typ`** — the JWT header's `typ` must be `keystone-identity+jwt`; reject
  anything else outright, so a JWT meant for something else on the same
  header can never be mistaken for this assertion.

What not to trust:

- Any header on this request that is not independently signed — in
  particular, a bare `X-Author-Email` with no `X-Keystone-Identity` next to
  it proves nothing; anything on the same network can send it.
- `roles`, whenever `rbac` is `"off"` — it is always `[]` in that case, and
  more generally reflects Keystone-MCP's policy at the moment of the call,
  not a durable grant your service should cache past this one request.

Reference implementations, with tests pinning them to the exact claim shape
above:

- **Python** — [`examples/keystone-identity/python/keystone_identity.py`](../examples/keystone-identity/python/keystone_identity.py)
  (`PyJWT>=2.8`, no other dependency):

  ```python
  from keystone_identity import IdentityError, verify_keystone_identity

  try:
      identity = verify_keystone_identity(
          request.headers.get("x-keystone-identity"),
          secrets=[os.environ["MYSVC_IDENTITY_SECRET"]],
          audience="mysvc-mcp",  # this entry's own `name`
      )
  except IdentityError as exc:
      raise ValueError(f"identity rejected: {exc}") from exc
  ```

- **TypeScript** — [`examples/keystone-identity/typescript/keystoneIdentity.ts`](../examples/keystone-identity/typescript/keystoneIdentity.ts)
  (`jose`, no other dependency):

  ```ts
  import { IdentityError, verifyKeystoneIdentity } from "./keystoneIdentity.js";

  try {
    const identity = await verifyKeystoneIdentity(header, {
      secrets: [process.env.MYSVC_IDENTITY_SECRET!],
      audience: "mysvc-mcp", // this entry's own `name`
    });
  } catch (err) {
    if (err instanceof IdentityError) throw new Error(`identity rejected: ${err.message}`);
    throw err;
  }
  ```

[`examples/hello-upstream/`](../examples/hello-upstream/) wires the Python
verifier into a real service (`HELLO_IDENTITY_SECRET`,
`HELLO_IDENTITY_AUDIENCE`) and refuses a call with a forged
`X-Author-Email` once it is configured — see its README for the exact
command. [`examples/keystone-identity/test-vector.json`](../examples/keystone-identity/test-vector.json)
is a fixed assertion both reference verifiers accept, for checking a new
implementation against the same token.

Why: [ADR 0003](adr/0003-signed-identity-assertion.md).

**Rotating the secret** without downtime: configure your service to accept
two secrets (both reference verifiers take a list, tried in order), restart
Keystone-MCP with the new `auth.identity_secret_env` value, then drop the old
secret from your service once you are sure no in-flight call still carries
an assertion signed with it (within `exp`'s margin of the restart).

### ES256 (many upstreams, no shared secret)

When many services need to verify who is calling and must not hold a signing
secret, set `KEYSTONE_MCP_IDENTITY_SIGNING_KEY` on Keystone-MCP (one EC P-256
PEM per deployment) and mark the registry entry with `auth.identity_alg: ES256`
instead of `auth.identity_secret_env`. Keystone-MCP signs `ES256`; upstreams
fetch the public key from
`{KEYSTONE_MCP_BASE_URL}/.well-known/keystone-identity-jwks.json` (same Host
allowlist as every other route — use a host from `KEYSTONE_MCP_BASE_URL` or
`KEYSTONE_MCP_ALLOWED_HOSTS`, not an arbitrary IP, or Host/Origin guard
returns 421). Claim shape and header `typ` are unchanged; only the algorithm
and verification path differ. HS256 with a per-upstream secret remains the
simple choice for one or two services. Rotation: replace
`KEYSTONE_MCP_IDENTITY_SIGNING_KEY` and restart; assertions expire within
minutes. Reference verifiers accept `jwks_url` / `jwksUrl` with
`algorithms: ["ES256"]`; see
[`test-vector-es256.json`](../examples/keystone-identity/test-vector-es256.json).

## Long-running tools

A tool that takes a while can report progress while it runs: send
`notifications/progress` against the `progressToken` on the incoming
request's `_meta` (every MCP SDK exposes this — e.g. `ctx.session.
report_progress(progress, total, message)` on the low-level Python SDK).
Keystone-MCP relays every one of those notifications to the client, in the
same call, for as long as it is still running — the client sees them exactly
as if it had called your service directly.

Whether anyone actually sees them is decided entirely on the client side,
not by the request your service received: a `progressToken` on that request
means Keystone-MCP's own MCP client library asked for progress, which it
always does, whether or not the real client did — your service cannot tell
the two apart. Keystone-MCP only relays a notification onward when the real
client sent its own `progressToken` to Keystone-MCP; otherwise it is
received and silently dropped. So send progress whenever you have a
meaningful update for a tool that may run long, the same way you would for
any other MCP client — you do not need to (and cannot reliably) guess
whether anyone downstream is listening.

Your service should treat cancellation like any other MCP server: on the
handshake protocol the Python SDK delivers it to your handler as
`asyncio.CancelledError`; on MCP 2026-07-28 it arrives when the client closes
the request stream. Release resources in `finally` blocks. Keystone-MCP forwards
a client cancel and applies the same upstream cancellation when a proxied call
hits the configured per-tool timeout.

## Asking the human (elicitation)

Before a destructive or ambiguous step, your tool may ask the connected MCP
client for confirmation. On the handshake protocol, call `elicit_form` (or the
equivalent in your SDK) while handling `tools/call`; Keystone forwards that
question when the client declared form-mode elicitation and
`KEYSTONE_MCP_PROXY_ELICITATION` is enabled (default). On MCP 2026-07-28,
return an `InputRequiredResult` with form-mode `ElicitRequest` entries from the
tool body instead of trying to open a back-channel mid-call.

Check that the client supports elicitation before asking; if it does not,
continue without a prompt or fail with a clear tool error. Do not ask for
passwords or other secrets through elicitation — the MCP specification
forbids it. URL-mode elicitation is declined by Keystone and never shown to
the client.

Keystone stops a tool call after at most **10** elicitation or `input_required`
rounds (including URL-mode auto-declines). Further asks fail the call or receive
`cancel` on the handshake protocol. All rounds share the configured per-tool
timeout.

## Running a stdio server

Why: [ADR 0012](adr/0012-stdio-upstreams-run-unsandboxed.md).

Some upstreams speak MCP over **stdio** instead of Streamable HTTP. Keystone-MCP
starts the child process, supervises it, and proxies calls the same way as for
HTTP — discovery, RBAC, progress, and cancellation all apply. There is no
`/healthz` on the child; availability is the process state (see
`keystone_mcp_upstream_available` in [observability-rbac.md](observability-rbac.md)).

Registry entry (no `url`):

```yaml
entries:
  - name: notes
    namespace: notes
    transport: stdio
    command: python
    args: ["/opt/notes/server.py"]
    cwd: /opt/notes
    enabled: true
    env:
      MY_API_KEY: MY_API_KEY_ENV
```

- **`command` / `args` / `cwd`** — how Keystone-MCP starts the server. Use an
  absolute path to the interpreter if `PATH` in the container is uncertain.
- **`env`** — maps **child variable name → parent environment variable name**.
  The child gets only the variables listed in `env` plus the MCP SDK's minimal
  set (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER`); Keystone-MCP never
  forwards its whole environment. Values must already be set in the Keystone-MCP
  process (or container) under the names on the right.
- **`auth.identity_secret_env`** — same HS256 assertion as HTTP, but it is sent
  in `params._meta["keystone-mcp/identity"]` on `tools/call`, `prompts/get`,
  and `resources/read`, not in `X-Keystone-Identity`. There is **no**
  `X-Author-Email` on stdio calls.
- **One process per entry** — started at startup (stdio connections start in
  parallel), discovered through, and restarted by the supervisor until shutdown.
- **stderr** from the child is copied into Keystone-MCP's logs (logger
  `keystone_mcp.upstream.stderr`), rate-limited (50 lines/s, bursts of 200);
  values of the entry's `env` and well-known token formats are masked.
- **Restarts** — if the process crashes or stops answering, the supervisor logs
  `upstream process down namespace=…` and restarts after a backoff (1 s, then
  doubling up to 60 s). A hang is detected after **three missed pings in a row**
  (about a minute with default timings); calls in flight fail at once and the
  process is restarted. A single slow ping no longer triggers a restart. After
  a run stays healthy for one minute, the backoff schedule resets to 1 s.
- **Progress and cancellation** — behave like HTTP upstreams (see "Long-running
  tools" above).
- **Elicitation** — upstream-to-user prompts are not forwarded for stdio (same
  gap as noted in [facade.md](facade.md#what-passes-through-the-door)).

Servers installed with `npx -y …` need Node in the Keystone-MCP image. Prefer
baking the package into the image and setting a generous
`discovery_timeout_seconds` on the entry. Minimal pattern:

```dockerfile
FROM ghcr.io/keystone-codes/keystone-mcp:0.5.0
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*
```

See [`../examples/hello-stdio/`](../examples/hello-stdio/) for a small Python
stdio server used in the demo compose stack.

## Resource publish filters

Tool filters (`include_prefixes`, `exclude_prefixes`, `tool_prefix`) do not
limit which resources or templates Keystone publishes. Optional registry fields:

- **`publish_resources`** — `true` (default) or `false`. When `false`, no
  resources or templates from that upstream are published; tools and prompts are
  unchanged.
- **`resource_include_prefixes`** / **`resource_exclude_prefixes`** — same
  prefix rules as `include_prefixes`; they match upstream `resource.name` and
  template `name`, not the URI and not `strip_prefix`.

Example:

```yaml
entries:
  - name: notes
    url: https://notes.internal/mcp
    namespace: notes
    include_prefixes: [notes_search, notes_get]
    publish_resources: true
    resource_include_prefixes: [handbook]
    resource_exclude_prefixes: [private_]
```

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
  `users`, `policy`, `service_accounts`, and `api_keys`.
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
    image: ghcr.io/keystone-codes/keystone-mcp:0.5.0
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
6. Verify `X-Keystone-Identity` (section above); set `auth.identity_secret_env`
   and drop any remaining trust in the unsigned `X-Author-Email`.

See [adding-routes.md](adding-routes.md) for the router-side configuration
(filters, multi-mounting, timeouts, schema patches) once the upstream meets
this contract.
