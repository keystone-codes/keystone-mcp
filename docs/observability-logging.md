# Application logging

This guide covers **production-ready logging** from Keystone-MCP: configuration,
log streams, redaction, and how to attach a collector on your platform. The
process does not ship Loki, Elasticsearch, or Vector as a required dependency —
only stdout/stderr and reference snippets under `docs/examples/`.

Keystone-MCP writes structured logs to **stderr**. The default format is
**NDJSON** (one JSON object per line) so log agents (Vector, Fluent Bit, cloud
logging) can parse fields without regex.

RBAC audit events (`rbac audit {...}`) and HTTP access lines share the same
pipeline but use different `stream` values. Prometheus metrics and RBAC audit
field semantics are in [observability-rbac.md](observability-rbac.md).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `KEYSTONE_MCP_LOG_LEVEL` | `INFO` | Root log level |
| `KEYSTONE_MCP_LOG_FORMAT` | `json` | `json` or `text` |
| `KEYSTONE_MCP_LOG_REDACT` | `true` | Redact secrets and PII in log lines |
| `KEYSTONE_MCP_LOG_ACCESS_ENABLED` | `true` | Platform access middleware (`stream=access`) |
| `KEYSTONE_MCP_LOG_REQUEST_ID_HEADER` | `X-Request-ID` | Correlation id from client |
| `KEYSTONE_MCP_LOG_REQUEST_ID_RESPONSE` | `true` | Echo correlation id on responses |

`configure_logging()` runs at startup in `python -m keystone_mcp.server` and in
the `keystone-mcp` CLI. It replaces `logging.basicConfig`.

Uvicorn’s access logger is **disabled** (`access_log=false`) so OAuth query
parameters never appear in default access lines. Use `keystone_mcp.access`
instead.

When `LOG_LEVEL` is not `DEBUG`, `httpx`, `httpcore`, and `uvicorn` loggers are
capped at `WARNING`.

## NDJSON fields

Common fields on every line:

| Field | Meaning |
| --- | --- |
| `ts` | UTC timestamp (ISO-8601) |
| `level` | Log level |
| `stream` | `app`, `access`, or `audit` |
| `logger` | Python logger name |
| `msg` | Message text |
| `request_id` | Correlation id when set on the request or context |

Access lines (`stream=access`, logger `keystone_mcp.access`) also include
`method`, `path` (no query string), `status`, `duration_ms`, and `client_ip`.
Authorization headers, cookies, and query strings are never logged.

Audit lines keep the legacy prefix `rbac audit` in `msg` with JSON payload;
`stream` is `audit`.

## Redaction

With `KEYSTONE_MCP_LOG_REDACT=true` (default), a filter redacts:

- Keystone API keys (`ksk_<key_id>_…`), including when the secret ends with `-`
  or `_`
- Keystone OAuth access and refresh tokens in free text (`km_at_…`, `km_rt_…`)
- `Bearer` tokens and common `token` / `password` / `authorization` patterns
- Bare JWTs and the `X-Keystone-Identity` header value
- Redis URLs that embed passwords
- Email addresses (replaced with `***@***`)

Subject pseudonyms in ordinary log lines use the same
`KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` as RBAC audit events.

Upstream mount logs record **namespace and host** only, not full URLs with
embedded credentials.

## Request correlation

The access middleware sets a context-scoped `request_id` from
`KEYSTONE_MCP_LOG_REQUEST_ID_HEADER` or a generated UUID. RBAC audit and
middleware observability reuse that id when present, then fall back to OAuth
session claims (`jti` / `sid`).

## Readiness

`GET /healthz` says the process is alive and always answers `200` once the
users-directory migrations have finished and the HTTP port is open; it never
checks a dependency, so `./scripts/deploy.sh` and the examples in this repo
keep using it for liveness. `GET /readyz` says this replica can serve work right
now. It runs four checks in parallel, each under a short timeout:

| Check | `ok` | `fail` | `skipped` | `pending` |
| --- | --- | --- | --- | --- |
| `redis` | `PING` succeeds | error or timeout | no Redis configured (`KEYSTONE_MCP_REDIS_URL` empty and no injected store) | — |
| `rbac_policy` | a policy is currently active | no policy has been loaded | `KEYSTONE_MCP_RBAC_MODE=off` | — |
| `users_directory` | the built-in database answers `SELECT 1` | the query errors or times out | `KEYSTONE_MCP_USERS_BACKEND=http` (external directory; see below), or no directory is wired at all | — |
| `bootstrap` | background startup finished | startup failed fatally | — | discovery or policy load still running |

The response is `{"status": "ok"}` (`200`) when every check is `ok` or
`skipped`, otherwise `{"status": "degraded"}` (`503`). The `checks` object is
added to the body only for callers judged internal the same way `/metrics` is
(source address in `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`, no
`X-Forwarded-For`, and an allowed `Host` — a name on the effective allowlist
or an IP literal) — but, unlike `/metrics`, an outside caller is never
refused and nothing is logged for it: a load balancer or container
healthcheck polls this route every few seconds from every replica.

The external users directory (`KEYSTONE_MCP_USERS_BACKEND=http`) is never
checked here, on purpose: that service already fails closed on every call
that needs it, and treating its outage as "this Keystone-MCP replica is not
ready" would pull every replica out of rotation over a problem no restart of
Keystone-MCP fixes. A transition into or out of the degraded state logs once
(`readiness degraded: <check>=fail (<ExceptionClassName>)` / `readiness
restored`), not on every poll; no URL, password, or exception message is
included, only the check name and the exception's class name.

## Operator smoke checks

When `KEYSTONE_MCP_LOG_FORMAT=json`, stderr carries only NDJSON — including
uvicorn and FastMCP messages and tracebacks (`exc_info` field) — through the
Keystone formatter and redaction filter.

After deploy, with JSON logging to a file or container logs:

```bash
# Access lines without query strings (works regardless of JSON spacing)
jq -c 'select(.stream=="access")' /var/log/keystone-mcp.log | head

# Compact JSON grep (matches Keystone's default JSON line shape)
grep '"stream":"access"' /var/log/keystone-mcp.log | head

# RBAC audit still present
grep 'rbac audit' /var/log/keystone-mcp.log | head

# No bearer tokens in recent output
! grep -E 'Bearer [A-Za-z0-9._-]{8,}' /var/log/keystone-mcp.log
```

## Vector reference

See [examples/vector-keystone.toml](examples/vector-keystone.toml) for a
minimal Vector sink configuration (reference only; not shipped in compose).
