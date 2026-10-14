# The facade

Keystone-MCP is the only MCP server the client talks to. Each backend keeps its
own language, its own business logic, and its own storage or vendor APIs.
Keystone-MCP authenticates the person, applies the role policy, and forwards the
call. It does not reimplement the service.

A service speaks MCP over Streamable HTTP, usually on `/mcp`, and exposes
`/healthz` for the process health check. It reads `X-Author-Email` when it
needs to know who is acting. That header is the verified identity. Roles are
not in it. The service trusts the header only on a private network Keystone-MCP
can reach, and it does not publish its MCP port on a public interface.

Keystone-MCP itself exposes the same `/healthz` convention, plus `GET /readyz`:
`/healthz` means the process is alive (liveness) and always answers `200`
once the users-directory migrations have finished and the HTTP port is open;
`/readyz` means this replica can actually serve work right now (readiness) —
it checks Redis, the active RBAC policy, the built-in users database, and
whether background startup (upstream discovery and policy load) has finished,
and answers `503` while any of them is down. Detail per check is in
[observability-logging.md](observability-logging.md#readiness).

The full contract is [connecting-services.md](connecting-services.md).
Mount options, timeouts and schema patches are
[adding-routes.md](adding-routes.md).

## Sections

An upstream entry is one URL plus a namespace. The namespace is the section
the client shows. A tool `search_widgets` in namespace `docs` is published as
`docs_search_widgets`.

List upstream services in a registry file and point
`KEYSTONE_MCP_UPSTREAMS_PATH` at it:

```yaml
schema_version: 1
entries:
  - name: mysvc
    url: http://mysvc-mcp:8081/mcp
    namespace: mysvc
    enabled: true
```

`http://` is fine on an internal Docker or Kubernetes network that is not
reachable from the internet. Set `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true`;
the production profile logs one warning at startup. Validate a file before
rollout:

```bash
keystone-mcp upstream validate --path /etc/keystone-mcp/upstreams.yaml
```

See `examples/upstreams-registry.example.yaml`. The same entries can be given
as a JSON array in `KEYSTONE_MCP_UPSTREAMS`; the registry file wins when both
are set. Upstream URLs are checked for SSRF-safe egress (HTTPS by default;
private or cleartext hosts need the explicit flags for internal networks
documented in [environment.md](environment.md)).

Prefix filters decide which of the service's tools enter that section:

- `include_prefixes` keeps tools whose name on the service starts with one of the prefixes
- `exclude_prefixes` drops tools after that, so an internal family never reaches the client

One service can be mounted more than once, each time as a different section.
`strip_prefix` removes the family prefix before the namespace is added, so
the client sees `billing_list_invoices` rather than
`billing_billing_list_invoices`.

Hiding has two layers. The prefix filter decides what Keystone-MCP is willing to
publish at all. The role policy decides which of those tools a given person
sees. A tool excluded by prefix is absent for everyone. A tool denied by
policy is absent for the roles that do not match.

Start order does not matter. A service that is down at startup is logged as a
warning and its tools appear on the next refresh
(`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`).

## Prompts and resources

Upstream prompts, resources and resource templates are published like tools:
the client sees prompts as `<namespace>_<upstream prompt name>` (``strip_prefix``
and ``tool_prefix`` trim tool names only, not prompts; ``include_prefixes`` /
``exclude_prefixes`` still apply to prompts by upstream name). Tool filters do
**not** apply to resources or templates — use ``publish_resources``,
``resource_include_prefixes`` and ``resource_exclude_prefixes`` on the registry
entry (same prefix rules as ``include_prefixes``; filters match upstream
``resource.name`` / template ``name``, not the URI). Resource URIs receive the
namespace (`scheme://<namespace>/...`, e.g. upstream `file:///handbook.md` becomes
`file://hello//handbook.md`). RBAC uses the same allow patterns as tools —
`<namespace>_<resource.name>` for both static resources and templates (the policy
file has no separate prompts or resources section). Two upstream resources that
share the same `name` get one RBAC name and one policy decision. Why:
[ADR 0011](adr/0011-rbac-by-name-for-prompts-and-resources.md).

Keystone-MCP publishes an upstream resource or resource template only when its
URI (template) starts with `scheme://`; others are skipped with a warning and
counted in `keystone_mcp_upstream_items_rejected_total`. `resources/read` is
checked against the resources and templates of the namespace the URI belongs
to (`scheme://<namespace>/…`). When the URI matches more than one of them,
every matching RBAC name must be allowed. Any URI that matches nothing published
is denied in `enforce` mode. The RBAC name of a resource must not equal a
published tool or prompt name — such a resource or template is not published
(startup warning, metric `reason="rbac_name_collision"`). In `enforce`, a
resource Keystone-MCP has no RBAC name for is not listed (reading it was already
refused).

Keystone does not publish `notifications/resources/updated` and does not
implement `resources/subscribe`. On MCP 2026-07-28 a client may subscribe via
`subscriptions/listen`, but Keystone never emits resource-update events.

Stdio upstreams receive the signed identity assertion in
`params._meta["keystone-mcp/identity"]` on `tools/call`, `prompts/get`, and
`resources/read` when `auth.identity_secret_env` (or ES256) is configured.
HTTP upstreams still use `X-Keystone-Identity`; unsigned subject headers on HTTP
are unchanged.

## Discovery

Startup order: migrate/seed the built-in users directory, open the HTTP port,
then run login-provider warm-up, stdio connection startup, upstream discovery,
and RBAC policy load in a background task. Until that task finishes,
`/readyz` answers `503` (`checks.bootstrap: pending` for internal callers),
including when `KEYSTONE_MCP_RBAC_MODE=off`. Startup refusals
(`KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true` with an unreachable upstream, or an
invalid policy) still exit with code `1` and the same message as before, but
only after `/healthz` has started answering — use `/readyz`, not an open port,
to know the replica is ready.

Keystone-MCP calls `list_tools()` on every enabled upstream and registers a live
proxy route for each tool that passes the filters. You do not register proxy
tools one by one.

**Stdio upstreams** use the same persistent child process for discovery and
proxying (no throwaway startup process). A stdio namespace becomes available
only after its catalog has been read; when the process comes up after a failed
discovery, the reconciler (or a one-shot discovery hook when refresh is
disabled) refreshes that namespace immediately instead of waiting for the next
tick.

HTTP upstream discovery opens **one MCP session** per upstream per refresh:
`tools/list`, `prompts/list`, `resources/list`, and `resources/templates/list`
run on that session instead of four separate connections. The upstream's
protocol era (MCP 2026-07-28 vs handshake) is learned on each discovery and
remembered for proxied calls: a tool call to an MCP 2026-07-28 upstream is a
single `tools/call` request; a handshake-era upstream gets one initialize
handshake per call plus the call itself.

Upstreams are discovered in parallel, each retried on its own
(`KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES`, default 3). An upstream that stays
unreachable does not block startup or the other upstreams: it is logged with
its namespace and reason, and retried on every refresh tick until it comes
up. HTTP discovery does not follow redirects (same as proxied tool calls):
point the registry `url` at the final MCP endpoint. If
`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=0` (the background refresh task
disabled), there is no refresh tick to retry it: the WARNING says so
("will not be retried; refresh is disabled") and the upstream stays
unreachable for the life of the process. Startup is refused only when every
configured upstream is unreachable with RBAC on, or when
`KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true` and at least one upstream is
unreachable. With `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=false` (default), an
unreachable upstream does not remove readiness after startup — `/readyz` stays
`503` only until discovery and policy load finish, then retries the upstream on
refresh ticks. With `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true`, any upstream
still unreachable at startup ends the process (after `/healthz` responds), and
after startup `/readyz` answers `503` while any configured upstream is
unavailable. Each upstream's reachability is exposed as
`keystone_mcp_upstream_available{namespace}` (1 = reachable).

An RBAC allow pattern that belongs only to an upstream namespace that is
currently unavailable does not refuse the policy either — it is logged as
"not verified" and checked once the namespace comes up; see "Unavailable
upstreams" in [`docs/rbac-policy-format.md`](rbac-policy-format.md#4-validation-rules).

While the process runs, **live discovery** re-reads each mounted upstream on a
timer (`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`, default 300). A tool added,
removed, or changed on a service is picked up without restarting Keystone-MCP.
A failed read for one namespace keeps the previous tool list for that namespace,
and the same rule applies to prompts, resources and resource templates.
An empty list must repeat on the next successful read before proxy tools (or
prompts, resources, templates) are removed.
If the refresh task itself fails, it is restarted after a delay (5 s, doubling
up to 5 min) and the failure is logged at ERROR. `SIGHUP` reloads the policy
inline when the task is not running.

The RBAC policy file and optional catalog snapshot are re-read on the same
timer when their bytes change, and immediately when you send `SIGHUP`
(`kill -HUP <pid>`). A file that fails validation is rejected and the last
good policy stays.

After a refresh tick that changed the tool catalog, reloaded the RBAC policy
or saw a users-directory change, Keystone-MCP sends
`notifications/tools/list_changed` to every open connection on that instance.
Clients on the handshake protocol receive it on the standalone SSE stream
(`GET` on the MCP endpoint); clients on MCP 2026-07-28 receive it on a
`subscriptions/listen` stream they open. A client that opens neither sees the
change on its next `tools/list`. Both the standalone `GET` stream and a
`subscriptions/listen` stream are long-lived connections — a load balancer
with an idle timeout should account for that (the SDK sends its own pings on
a `subscriptions/listen` stream while it waits).

Proxied tools are published with the upstream's own `inputSchema` (after
`KEYSTONE_MCP_PROXY_SCHEMA_PATCHES`), `outputSchema` (only when
`KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=false`), `title` and `annotations`.
Keystone-MCP does not validate arguments against that schema; the upstream
does. It also does not re-validate a tool **answer** against the upstream's
`outputSchema` — the answer is forwarded as returned.

## Built-in tools

Keystone-MCP's own, not proxied:

- `users_list`, `users_add`, `users_update`, `users_block`, `users_unblock`,
  `users_set_roles`, `users_grant_role`, `users_revoke_role` — the users
  directory, from the agent. Published only when
  `KEYSTONE_MCP_RBAC_MODE=enforce`. Who may call them is the policy file. See
  [users.md](users.md).
- `policy_read`, `policy_catalog`, `policy_validate`, `policy_role_set`,
  `policy_role_delete`, `policy_allow_add`, `policy_allow_remove`,
  `policy_list_set`, `policy_rollback` — change the RBAC policy from the agent.
  Published only when `KEYSTONE_MCP_RBAC_MODE=enforce` and
  `KEYSTONE_MCP_POLICY_TOOLS` is not `off`; mutation tools need `full` and a
  writable policy file. See [policy-admin.md](policy-admin.md) and
  [rbac-policy-format.md](rbac-policy-format.md).

File transfer is not built in: run a file service as an upstream MCP server
(see [connecting-services.md](connecting-services.md)). Why: [ADR 0006](adr/0006-no-file-api-in-the-core.md).

## A call, end to end

1. OAuth has already turned the connection into a verified identity.
2. The throttle counts the call, once, before the users directory is touched.
3. RBAC, when it is on, allows or denies. The catalog filter uses the same decision.
4. The router dispatches to a built-in tool or to the upstream proxy.
5. The proxy forwards the call with `X-Author-Email` and the configured timeout.
6. Progress notifications from the upstream are relayed to the client while
   the call runs, when the client asked for them.
7. If the client cancels or the per-tool timeout expires, Keystone-MCP forwards
   that cancellation to the upstream request (see the table below).
8. The upstream's answer goes back unchanged: every content block,
   `structuredContent`, `isError`. With `KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=true`
   it is wrapped in `{state, tool, task_id, result}` and a `status` of
   `error`, `refused` or `accepted` is mapped to an error, a rate-limit
   error, or a pending task.

`task_id` is derived from the verified identity, the tool name and the
canonical arguments, so a retry is recognizable as the same task.

## What passes through the door

Keystone-MCP is a full MCP server on both sides, not a dumb pipe: only the
parts of the protocol listed below cross it. Anything not listed is either
not implemented yet or deliberately never forwarded.

| Mechanism | Status |
|---|---|
| `tools/list`, `tools/call` | yes; on `tools/call`, `Mcp-Param-*` headers are derived from the tool's `inputSchema` (`x-mcp-header`) on every HTTP upstream call |
| `notifications/progress` (upstream → client) | yes, when the client sends a `progressToken`; both protocol eras |
| `notifications/tools/list_changed` | yes, after a catalog change, an RBAC policy reload or a users-directory change; both protocol eras — see "Discovery" above |
| `notifications/cancelled` (client → upstream) | yes: a client cancel or a keystone-mcp timeout is forwarded to the upstream request (as `notifications/cancelled` on the handshake protocol, by closing the request stream on MCP 2026-07-28) |
| `prompts/list`, `prompts/get` | yes |
| `notifications/prompts/list_changed` | yes, after an upstream prompt catalog change; both protocol eras |
| `resources/list`, `resources/read`, `resources/templates/list` | yes |
| `notifications/resources/list_changed` | yes, after an upstream resource catalog change; both protocol eras |
| `resources/subscribe`, `notifications/resources/updated` | no |
| `elicitation/create` (upstream → user) | yes for HTTP upstreams: form mode only, prefixed with `[namespace]`; URL mode is declined; not for stdio upstreams. On MCP 2026-07-28 the question reaches the client as an `input_required` result of the tool call; a 2026-07-28 client cannot be asked by an upstream that speaks the handshake protocol (the upstream gets `decline`). At most 10 question rounds per tool call (automatic declines and questions to the user alike); the whole exchange counts against the tool timeout |
| `sampling/createMessage`, `roots/list` | no, by design: needs its own trust model |
| `notifications/message` (upstream logs) | no: upstream logs stay with the upstream |
| `completion/complete` | no |
| MCP tasks (`tasks/*`) | no |

Tool and prompt results forward the upstream's `_meta` except connection stamps
(`io.modelcontextprotocol/serverInfo`, `protocolVersion`, `clientInfo`,
`clientCapabilities`); other keys pass through unchanged.

Same rows apply to **stdio upstreams**, except `elicitation/create` (upstream →
user), which is not forwarded for stdio either.

Upstream elicitation text is written by the service; the human sees the
service namespace in the question prefix. Time spent answering counts against
the tool-call timeout (on MCP 2026-07-28 each guard round is a separate call).
With more than one Keystone replica, a repeat call after a question must hit
the same instance — `request_state` is sealed with a process-local key unless
you configure shared state elsewhere.

## Custom routes

The usual path is a whole upstream server. A custom route is for a tool
Keystone-MCP itself should execute. Every route goes through the `Adapter`
protocol in `src/keystone_mcp/adapters/base.py`. The built-in catalog in
`src/keystone_mcp/catalog/builtin.py` is the pattern.

`stub.StubAdapter` is a stand-in response until the real adapter exists.
Reference adapters for forks (`WebhookAdapter`, `ExternalHttpAdapter`) live in
`keystone_mcp.contrib.adapters`: see
[contrib/adapters.md](contrib/adapters.md).

Register with `mode="stub"` while the target is being built, then
`registry.set_mode(name, "live")`. Transport, identity and `task_id` stay
the same.

Business logic for a domain stays in the upstream service. A custom adapter
is for a platform primitive, not for re-hosting that domain inside Keystone-MCP.

## Audit and metrics

Every allow and deny, and every `users_*` mutation, can be written to the
audit log. Subject identifiers in that log are pseudonyms. The salt
(`KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT`) is required whenever RBAC and audit
are both on.

`GET /metrics` is optional and has no credential. It is limited by source
address (`KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`) and, like every route
except `/healthz`/`/readyz`, by the `Host` allowlist
(`KEYSTONE_MCP_ALLOWED_HOSTS`). Fields and example alerts:
[observability-rbac.md](observability-rbac.md).

## Limits

- Upstream HTTP response bodies are capped at
  `KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES` (default 16 MiB); stdio upstreams
  have no response cap. Each tool's `inputSchema` and `outputSchema` must fit
  in `KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES` (default 64 KiB); additionally,
  any JSON Schema `pattern` or `patternProperties` key longer than 512
  characters, or nesting deeper than 64 levels, causes the tool to be skipped
  (warning and metric). Catalog reads refuse more than
  `KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS` (default 2000) tools, prompts,
  resources, or templates per upstream per kind — a failed tools list marks
  the upstream unavailable; a failed prompts/resources read keeps the previous
  catalog for that kind.
- The throttle (when `KEYSTONE_MCP_THROTTLE_BACKEND=memory`), the users-directory
  cache and the circuit breaker are per-process; live discovery (the catalog of
  published tools) is per-process too. With `KEYSTONE_MCP_THROTTLE_BACKEND=redis`,
  tool-call and sign-in IP limits are shared in Redis. What that means with more
  than one replica: [environment.md](environment.md#more-than-one-replica).
- Changing `KEYSTONE_MCP_UPSTREAMS_PATH`, `KEYSTONE_MCP_UPSTREAMS`, proxy schema
  patches, or per-tool timeouts still requires a process restart.
- When RBAC is enabled, startup is refused only if every configured upstream
  is unreachable, not running with an empty live catalog; a single
  unreachable upstream among several is a warning, not a refusal.
- Access and refresh tokens are opaque and Redis-backed. Blocking a person or
  calling `users_logout` revokes every access and refresh token for that
  person immediately (see [users.md](users.md)).
- Refresh tokens have an idle TTL (`KEYSTONE_MCP_REFRESH_TOKEN_TTL`): each
  use resets the clock.
- The policy and catalog snapshot shipped in this repository cover the
  built-in tools only. A deployment brings its own policy for its own
  upstream tools.

## Security model

- Identity comes only from validated token claims. Downstream services see it as `X-Author-Email`.
- With RBAC `enforce`, a tool that no allow pattern of the caller's roles matches is denied and does not appear in the catalog.
- `rbac_mode=off` means no authorization is enforced. Startup logs every administrative tool that is then reachable by any authenticated caller.
- `/metrics` and `/internal/*` carry no credential. The introspection route is off by default.
- The public network is given one port, Keystone-MCP's. Service MCP ports, Redis, and databases are not published. See the network diagram in [security-model.md](security-model.md#trust-zones).
- Report a vulnerability as described in [SECURITY.md](../SECURITY.md).
