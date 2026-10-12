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
`/healthz` means the process is alive (liveness) and always answers `200`;
`/readyz` means this replica can actually serve work right now (readiness) —
it checks Redis, the active RBAC policy, and the built-in users database, and
answers `503` while any of them is down. Detail per check is in
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

## Discovery

Keystone-MCP calls `list_tools()` on every enabled upstream and registers a live
proxy route for each tool that passes the filters. You do not register proxy
tools one by one.

Upstreams are discovered in parallel, each retried on its own
(`KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES`, default 3). An upstream that stays
unreachable does not block startup or the other upstreams: it is logged with
its namespace and reason, and retried on every refresh tick until it comes
up. If `KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=0` (the background refresh task
disabled), there is no refresh tick to retry it: the WARNING says so
("will not be retried; refresh is disabled") and the upstream stays
unreachable for the life of the process. Startup is refused only when every
configured upstream is unreachable with RBAC on, or when
`KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true` and at least one upstream is
unreachable. Each upstream's reachability is exposed as
`keystone_mcp_upstream_available{namespace}` (1 = reachable).

An RBAC allow pattern that belongs only to an upstream namespace that is
currently unavailable does not refuse the policy either — it is logged as
"not verified" and checked once the namespace comes up; see "Unavailable
upstreams" in [`docs/rbac-policy-format.md`](rbac-policy-format.md#4-validation-rules).

While the process runs, **live discovery** re-reads each mounted upstream on a
timer (`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`, default 300). A tool added,
removed, or changed on a service is picked up without restarting Keystone-MCP.
A failed read for one namespace keeps the previous tool list for that namespace.
An empty list must repeat on the next tick before proxy tools are removed.
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
does.

## Built-in tools

Keystone-MCP's own, not proxied:

- `users_list`, `users_add`, `users_update`, `users_block`, `users_unblock`,
  `users_set_roles`, `users_grant_role`, `users_revoke_role` — the users
  directory, from the agent. Published only when
  `KEYSTONE_MCP_RBAC_MODE=enforce`. Who may call them is the policy file. See
  [users.md](users.md).

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
| `tools/list`, `tools/call` | yes |
| `notifications/progress` (upstream → client) | yes, when the client sends a `progressToken`; both protocol eras |
| `notifications/tools/list_changed` | yes, after a catalog change, an RBAC policy reload or a users-directory change; both protocol eras — see "Discovery" above |
| `notifications/cancelled` (client → upstream) | yes: a client cancel or a keystone-mcp timeout is forwarded to the upstream request (as `notifications/cancelled` on the handshake protocol, by closing the request stream on MCP 2026-07-28) |
| `prompts/*` | not yet |
| `resources/*` | not yet |
| `elicitation/create` (upstream → user) | under evaluation |
| `sampling/createMessage`, `roots/list` | no, by design: needs its own trust model |
| `notifications/message` (upstream logs) | no: upstream logs stay with the upstream |
| `completion/complete` | no |
| MCP tasks (`tasks/*`) | no |

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

- The throttle, the users-directory cache and the circuit breaker are
  per-process; live discovery (the catalog of published tools) is
  per-process too. What that means with more than one replica:
  [environment.md](environment.md#more-than-one-replica).
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
