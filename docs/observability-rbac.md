# RBAC observability — audit logs and Prometheus metrics

This guide covers **metrics and RBAC audit** — the production-ready Prometheus
surface and structured authorization events. General application logging (access
lines, NDJSON format, redaction, `request_id`, log agents) is in
[observability-logging.md](observability-logging.md).

Keystone-MCP emits structured audit events (`rbac audit {...}` in application logs)
and optional Prometheus metrics for authorization decisions, tool calls, catalog
refresh, and `users_*` mutations. This document lists configuration, metric names,
and example alert rules for operations teams.

**Deployment note:** Keystone-MCP is the **source** of events and metrics.
Wiring alert rules into Alertmanager/Prometheus and building dashboards is a
deployment-side concern, not something this repository ships.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `KEYSTONE_MCP_RBAC_AUDIT_ENABLED` | `true` | Structured audit log events |
| `KEYSTONE_MCP_RBAC_AUDIT_LIST_TOOLS_SAMPLE_RATE` | `0.1` | Sample successful list-tools allows (denies never sampled) |
| `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` | empty | Pepper for SHA-256 subject pseudonyms — **set in production** |
| `KEYSTONE_MCP_METRICS_ENABLED` | `false` | Expose `GET /metrics` (no authentication) |
| `KEYSTONE_MCP_METRICS_PATH` | `/metrics` | Metrics route when enabled |

When `KEYSTONE_MCP_METRICS_ENABLED=true`, `/metrics` answers only a caller
whose source address is in `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS` (default
loopback) and whose request carries no `X-Forwarded-For`; like every route
except `/healthz`/`/readyz`, it also needs an allowed `Host`
(`KEYSTONE_MCP_ALLOWED_HOSTS`). There is no credential on it by design.

Tool-call metrics label `namespace` (and `tool_family`) with the coarse prefix
from the published tool name — the segment before the first `_`, same as RBAC
`tool_family`. No email, subject, or role labels appear on these series.

When RBAC (`KEYSTONE_MCP_RBAC_MODE=observe` or `enforce`) and audit are both on
and the audit salt is empty, startup refuses to start rather than emit
subject identifiers that are guessable from an email address — see
`config.py::validate_settings`.

## Audit event types

### `rbac_authz_decision`

Emitted on RBAC middleware allow/deny (list-tools and call-tool). Subject is
`sub_<16 hex>` (never raw email). Includes `policy_version`, `policy_content_hash`,
`reason`, `cache_hit`, `operation`, `login_provider` (the sign-in method's
name, e.g. `google` or `api_key` — lets a `human_identity_required` denial be
read without a separate token lookup).

### `rbac_users_mutation`

Emitted for every `users_*` admin tool attempt, including ambiguous outcomes
(`service_timeout`, `service_unavailable`, validation errors). Fields: `actor`,
`target`, `operation`, `outcome`, `code`, `task_id`, `role` (grant/revoke),
`roles_before` / `roles_after` when available from the users directory.

### `rbac_policy_mutation`

Emitted for every `policy_*` admin tool attempt. Includes `actor_subject_type`
when the verified identity carries a subject type (for example `service` on a
refusal).

### `oauth_session`

OAuth rotation and replay events. Fields: `action` (`grace_reissue`,
`refresh_replay`, `code_replay`, …), hashed `subject`, `client_id`,
`revoked_tokens` when tokens were dropped, optional `reason` and `delay_ms`
(grace reissue only). Never includes raw tokens or email.

## Prometheus metrics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `keystone_mcp_rbac_decisions_total` | `decision`, `reason`, `tool_family`, `operation` | Allow/deny counts (`operation` = `list_tools` or `call_tool`) |
| `keystone_mcp_tool_call_attempts_total` | `tool_family`, `namespace`, `tool`, `auth_method`, `oauth_client_id` | Every `call_tool` entering the stack (outer throttle) |
| `keystone_mcp_tool_invocations_total` | same + `outcome` | Handler reached (`outcome` = `success`, `tool_error`, `error`, `cancelled`) |
| `keystone_mcp_tool_invocation_seconds` | same + `outcome` | Handler latency histogram (`outcome` includes `cancelled`) |
| `keystone_mcp_rbac_directory_resolve_total` | `outcome` | `cache_hit`, `miss`, `unavailable`, `error` |
| `keystone_mcp_rbac_directory_resolve_seconds` | (histogram) | Resolve latency |
| `keystone_mcp_rbac_policy_reload_total` | `success` | Policy load/reload (`true` / `false`) |
| `keystone_mcp_catalog_refresh_total` | `outcome` | Upstream catalog refresh (`unchanged` / `held` / `applied`) |
| `keystone_mcp_catalog_refresh_changes_total` | `direction` | Tools added or removed (`added` / `removed`; counts only, no tool names) |
| `keystone_mcp_upstream_available` | `namespace` | 1 if the upstream is considered available, else 0. For HTTP: last discovery or refresh succeeded. **For stdio: the supervised process is running** (not in `backoff` / `stopped`). |
| `keystone_mcp_upstream_process_restarts_total` | `namespace` | Cumulative restarts of a stdio upstream child after crash, hang, or failed start |
| `keystone_mcp_upstream_items_rejected_total` | `namespace`, `kind`, `reason` | Catalog items Keystone refused to publish or pass on. `kind`: `tool`, `prompt`, `resource`, `template`, `catalog`, or `response`. `reason` (at 0.6.0): `name_collision`, `unpublishable_schema`. Increments on every reconciliation attempt while the condition persists. |
| `keystone_mcp_upstream_input_rounds_exceeded_total` | `namespace` | Tool calls stopped because the upstream kept requesting input |
| `keystone_mcp_list_changed_sessions_total` | `kind` | Sessions notified that a list of tools/prompts/resources changed. A "session" is a handshake-era connection or an open `subscriptions/listen` stream |
| `keystone_mcp_users_mutation_total` | `operation`, `outcome` | Admin mutation attempts |
| `keystone_mcp_admin_refusals_total` | `operation`, `reason` | Built-in administration refusals (`reason` includes `service_account`) |
| `keystone_mcp_oauth_client_registrations_total` | `outcome` | `POST /register` outcomes (`created`, `rejected_limit`, `rejected_redirect_host`, `rejected_metadata`) |
| `keystone_mcp_oauth_client_evictions_total` | (counter) | Unused OAuth clients evicted to admit a new registration at `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` |
| `keystone_mcp_oauth_token_exchange_total` | `grant_type`, `outcome` | OAuth `/token` exchanges (`issued`, `grace_reissue`, `replay_revoked`, `code_replay`, …) |
| `keystone_mcp_oauth_clients` | (gauge) | Live registered OAuth clients, refreshed on every registration attempt on this replica |
| `keystone_mcp_api_key_verifications_total` | `outcome` | API key checks at the directory resolver (`valid`, `invalid`, `malformed`, `unknown_key_id`, `limited`, `unavailable`) |
| `keystone_mcp_api_key_cache_entries` | `cache` | Entries in the positive/negative API key verification caches (`positive`, `negative`) |
| `keystone_mcp_api_key_cache_evictions_total` | `cache` | LRU evictions from those caches |
| `keystone_mcp_users_revision_bump_failed_total` | — | Users-directory revision `INCR` failed after a successful mutation on this replica |

`keystone_mcp_oauth_clients` is a per-replica gauge: it is set to the result of
the store's client count right after each registration attempt on that
replica, not a cluster-wide total, so two replicas can briefly report
different values for the same shared Redis store.

On tool-call series, `tool`, `tool_family`, and `namespace` are taken only from
names published in the live tool, prompt, and resource catalogs; anything else
is reported as `unknown` (including random tool names from the client). Do not
publish a service whose namespace is `unknown`, or its metrics will mix with
unpublished names.

`tool` is the full published name when `KEYSTONE_MCP_METRICS_TOOL_NAME=full`
(default), or the namespace prefix when `coarse`. `auth_method` is the
access-token claim (`google`, `api_key`, …) or `none`. `oauth_client_id` is
the registered OAuth client id or `none` / `unknown`. Email never appears in
labels.

To bound Prometheus time-series cardinality, each process keeps at most
`KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT` (default 50) distinct
`oauth_client_id` values; the first N clients seen by that process keep
their own label for its lifetime, and every client seen after that is
reported as `other`. On a deployment with several replicas, which client
ids are "first" can differ per replica, so the set of concrete ids folded
into `other` is not guaranteed to match across replicas.

## Example PromQL alert rules

Use these as templates for your own Prometheus/Alertmanager configuration.
Adjust windows and thresholds per environment.

### Unauthenticated API-key traffic

```promql
sum(rate(keystone_mcp_api_key_verifications_total{outcome=~"unknown_key_id|malformed|limited"}[5m])) > 50
```

### Users revision bump failures

```promql
increase(keystone_mcp_users_revision_bump_failed_total[15m]) > 0
```

### OAuth refresh or code replay (possible token theft)

```promql
increase(keystone_mcp_oauth_token_exchange_total{outcome=~"replay_revoked|code_replay"}[15m]) > 0
```

### Mass RBAC denials (possible misconfiguration or attack)

```promql
sum(rate(keystone_mcp_rbac_decisions_total{decision="deny"}[5m])) > 10
```

Per-reason drill-down (distinguish permission vs infrastructure):

```promql
sum by (reason) (rate(keystone_mcp_rbac_decisions_total{decision="deny"}[5m]))
```

Alert when fail-closed directory errors dominate (not `not_permitted`):

```promql
sum(rate(keystone_mcp_rbac_decisions_total{decision="deny",reason="roles_unavailable"}[5m]))
  > 1
```

### Users directory unavailable (fail-closed)

```promql
sum(rate(keystone_mcp_rbac_directory_resolve_total{outcome="unavailable"}[5m])) > 0
```

Or sustained circuit-open / errors:

```promql
sum(rate(keystone_mcp_rbac_directory_resolve_total{outcome=~"unavailable|error"}[5m]))
  / sum(rate(keystone_mcp_rbac_directory_resolve_total[5m])) > 0.5
```

### Policy hot-reload rollback

Alert when reload attempts fail (previous snapshot kept):

```promql
sum(rate(keystone_mcp_rbac_policy_reload_total{success="false"}[15m])) > 0
```

### Tool call volume and errors

Per published tool (requires `KEYSTONE_MCP_METRICS_TOOL_NAME=full`):

```promql
sum by (tool, auth_method) (rate(keystone_mcp_tool_invocations_total[5m]))
```

Error ratio for a namespace:

```promql
sum(rate(keystone_mcp_tool_invocations_total{tool_family="docs",outcome!="success"}[5m]))
  / sum(rate(keystone_mcp_tool_invocations_total{tool_family="docs"}[5m]))
```

### Users admin mutations — errors and ambiguous outcomes

```promql
sum by (operation, outcome) (rate(keystone_mcp_users_mutation_total{outcome="error"}[5m])) > 0
```

Timeout / unavailable from adapter (audit log code `service_timeout` /
`service_unavailable`; metric `outcome=error`):

```promql
sum(rate(keystone_mcp_users_mutation_total{outcome="error"}[5m])) > 0.1
```

## Log-based investigation

Grep application logs for structured audit lines:

```bash
docker logs keystone-mcp 2>&1 | grep 'rbac audit' | grep 'rbac_authz_decision'
docker logs keystone-mcp 2>&1 | grep 'rbac audit' | grep 'rbac_users_mutation'
```

Correlate `task_id` on mutations with the router's `task_id` for end-to-end tracing.

## Host-installed MCP (local Prometheus example)

When Keystone MCP runs on the host (for example `systemd` on `127.0.0.1:8080`) with
`KEYSTONE_MCP_METRICS_ENABLED=true`, a minimal Prometheus sidecar lives in
`prometheus/example/`. It uses **host networking** to scrape loopback and
listens on **`127.0.0.1:9091`** only (port `9090` is often already taken elsewhere).

With a non-loopback `KEYSTONE_MCP_BASE_URL` (any production host), also set
`KEYSTONE_MCP_ALLOWED_HOSTS=127.0.0.1:8080` on Keystone-MCP: the scrape
arrives with `Host: 127.0.0.1:8080`, which the Host guard otherwise refuses
with `421`.

```bash
cd /path/to/keystone-mcp
docker compose -f prometheus/example/docker-compose.yml up -d
```

On the server, confirm the target is up: `curl -sS http://127.0.0.1:9091/api/v1/targets`
and query `keystone_mcp_tool_call_attempts_total` in the Prometheus UI.

## Related

- [rbac-policy-format.md](rbac-policy-format.md) — the RBAC policy file and
  catalog snapshot format
- [rbac-role-matrix-per-tool.md](rbac-role-matrix-per-tool.md) — the generated
  per-tool role matrix for the shipped default policy
