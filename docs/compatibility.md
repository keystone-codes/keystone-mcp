# Public compatibility (0.5.0)

From release 0.5.0 onward, the items below are the public contract of
Keystone-MCP. Until 2.0.0 the contract may only grow: new optional settings,
fields, tools, metrics and routes are allowed in minor releases. Deprecated
items stay working until the next major version. Anything not listed here may
change in any release with a note in [CHANGELOG.md](../CHANGELOG.md).

Defaults, allowed values and operational detail for environment variables are
in [environment.md](environment.md). This page names what is frozen.

## Environment variables

Since 0.6.0, a non-empty boolean value outside the accepted words is refused at
startup (security fix); values that never worked (non-positive TTL, port out of
range, `BASE_URL` without http(s) scheme, empty request-id header, metrics path
without `/` or equal to the MCP path) are refused at startup.

| Variable | Frozen since | Status |
|---|---|---|
| `KEYSTONE_MCP_ALLOWED_HOSTS` | 0.5.0 | stable |
| `KEYSTONE_MCP_AUTH_CODE_TTL` | 0.5.0 | stable |
| `KEYSTONE_MCP_BASE_URL` | 0.5.0 | stable |
| `KEYSTONE_MCP_DEPLOYMENT_PROFILE` | 0.5.0 | stable |
| `KEYSTONE_MCP_DEV_TOKENS` | 0.5.0 | stable |
| `KEYSTONE_MCP_DEV_TOKENS_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_ENABLED_LOGIN_METHODS` | 0.5.0 | deprecated (since 0.5.0, use KEYSTONE_MCP_LOGIN_PROVIDERS_PATH) |
| `KEYSTONE_MCP_ENV_FILE` | 0.5.0 | stable |
| `KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN` | 0.5.0 | deprecated (since 0.5.0, use KEYSTONE_MCP_LOGIN_PROVIDERS_PATH) |
| `KEYSTONE_MCP_GOOGLE_CLIENT_ID` | 0.5.0 | deprecated (since 0.5.0, use KEYSTONE_MCP_LOGIN_PROVIDERS_PATH) |
| `KEYSTONE_MCP_GOOGLE_CLIENT_SECRET` | 0.5.0 | deprecated (since 0.5.0, use KEYSTONE_MCP_LOGIN_PROVIDERS_PATH) |
| `KEYSTONE_MCP_GOOGLE_CLIENT_SECRET_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_HOST` | 0.5.0 | stable |
| `KEYSTONE_MCP_HTTP_PATH` | 0.5.0 | stable |
| `KEYSTONE_MCP_IDENTITY_SIGNING_KEY` | 0.5.0 | stable |
| `KEYSTONE_MCP_IDENTITY_SIGNING_KEY_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS` | 0.6.0 | stable |
| `KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS` | 0.5.0 | stable |
| `KEYSTONE_MCP_INTERNAL_ENDPOINTS_ENABLED` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_IDENTITY_BINDING` | 0.6.0 | stable |
| `KEYSTONE_MCP_LOGIN_BRAND` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_DEFAULT_LANG` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_PENDING_TXN_TTL` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_THROTTLE_EMAIL_MAX` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOG_ACCESS_ENABLED` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOG_FORMAT` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOG_LEVEL` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOG_REDACT` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOG_REQUEST_ID_HEADER` | 0.5.0 | stable |
| `KEYSTONE_MCP_LOG_REQUEST_ID_RESPONSE` | 0.5.0 | stable |
| `KEYSTONE_MCP_OTEL_ENABLED` | 0.6.0 | stable |
| `KEYSTONE_MCP_METRICS_ENABLED` | 0.5.0 | stable |
| `KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT` | 0.5.0 | stable |
| `KEYSTONE_MCP_METRICS_PATH` | 0.5.0 | stable |
| `KEYSTONE_MCP_METRICS_TOOL_NAME` | 0.5.0 | stable |
| `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` | 0.5.0 | stable |
| `KEYSTONE_MCP_OAUTH_DCR_ENABLED` | 0.5.0 | stable |
| `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` | 0.5.0 | stable |
| `KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS` | 0.6.0 | stable |
| `KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX` | 0.5.0 | stable |
| `KEYSTONE_MCP_POLICY_TOOLS` | 0.5.0 | stable |
| `KEYSTONE_MCP_PORT` | 0.5.0 | stable |
| `KEYSTONE_MCP_PRIMARY_LOGIN_METHOD` | 0.5.0 | deprecated (since 0.5.0, use KEYSTONE_MCP_LOGIN_PROVIDERS_PATH) |
| `KEYSTONE_MCP_PROXY_ELICITATION` | 0.5.0 | stable |
| `KEYSTONE_MCP_PROXY_SCHEMA_PATCHES` | 0.5.0 | stable |
| `KEYSTONE_MCP_PROXY_STATUS_ENVELOPE` | 0.5.0 | stable |
| `KEYSTONE_MCP_RBAC_AUDIT_ENABLED` | 0.5.0 | stable |
| `KEYSTONE_MCP_RBAC_AUDIT_LIST_TOOLS_SAMPLE_RATE` | 0.5.0 | stable |
| `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` | 0.5.0 | stable |
| `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT` | 0.5.0 | stable |
| `KEYSTONE_MCP_RBAC_MODE` | 0.5.0 | stable |
| `KEYSTONE_MCP_RBAC_POLICY_PATH` | 0.5.0 | stable |
| `KEYSTONE_MCP_REDIS_KEY_PREFIX` | 0.5.0 | stable |
| `KEYSTONE_MCP_REDIS_URL` | 0.5.0 | stable |
| `KEYSTONE_MCP_REDIS_URL_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS` | 0.5.0 | stable |
| `KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` | 0.6.0 | stable |
| `KEYSTONE_MCP_REFRESH_TOKEN_TTL` | 0.5.0 | stable |
| `KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS` | 0.6.0 | stable |
| `KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR` | 0.5.0 | stable |
| `KEYSTONE_MCP_SUPERADMIN_EMAIL` | 0.5.0 | stable |
| `KEYSTONE_MCP_THROTTLE_MAX` | 0.5.0 | stable |
| `KEYSTONE_MCP_THROTTLE_WINDOW` | 0.5.0 | stable |
| `KEYSTONE_MCP_THROTTLE_BACKEND` | 0.6.0 | stable |
| `KEYSTONE_MCP_TOKEN_TTL` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAMS` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAMS_PATH` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_DISCOVERY_TIMEOUT` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS` | 0.5.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES` | 0.6.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES` | 0.6.0 | stable |
| `KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS` | 0.6.0 | stable |
| `KEYSTONE_MCP_USERS_BACKEND` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_BACKEND_CONFIG` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_CACHE_DENY_TTL_SECONDS` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_CIRCUIT_FAILURE_THRESHOLD` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_CIRCUIT_RECOVERY_SECONDS` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_DB_URL` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_DB_URL_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_USERS_DELETE_MODE` | 0.6.0 | stable |
| `KEYSTONE_MCP_USERS_REDIS_REVISION_KEY` | 0.5.0 | stable |
| `KEYSTONE_MCP_POLICY_REDIS_REVISION_KEY` | 0.6.0 | stable |
| `KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP` | 0.6.0 | stable |
| `KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_SERVICE_TOKEN` | 0.5.0 | stable |
| `KEYSTONE_MCP_USERS_SERVICE_TOKEN_FILE` | 0.6.0 | stable |
| `KEYSTONE_MCP_USERS_SERVICE_URL` | 0.5.0 | stable |

What is frozen for each variable: its name, meaning, default, and the set of
allowed values. Adding a new allowed value is not a breaking change.

Variables named in the upstream registry (`auth.bearer_env`,
`auth.identity_secret_env`, and the values in a stdio entry's `env` map) are
chosen by you; their names are not part of this contract. The same `<NAME>_FILE`
rule as for built-in secrets applies to those operator-chosen names (see
[environment.md#secrets-from-files](environment.md#secrets-from-files)).
`KEYSTONE_MCP_CONTRIB_*` variables belong to contrib and are not covered (see
[contrib/README.md](contrib/README.md)). Removed variables:
[environment.md#removed-variables](environment.md#removed-variables).

## Policy file

Frozen since 0.5.0. Normative format:
[rbac-policy-format.md](rbac-policy-format.md); loader contract:
`src/keystone_mcp/rbac/policy.py`.

- `version` is any non-empty string; Keystone does not interpret it.
- Top-level keys (unknown keys are rejected): `version`, `default_deny`
  (must be `true`), `roles` (`<name>: {description, allow: [...]}`), `deny`,
  `requires_human_identity`, `critical_tools`, `reserved_allow_patterns`,
  `tool_dispositions`.
- Semantics: glob patterns (`fnmatch`); `*` matches every published tool;
  effective allow is the union of all roles held; global `deny` overrides any
  `allow`; anything that does not match an allow is denied when
  `default_deny` is `true`.
- Format versioning: a new optional top-level key is not breaking. Removing a
  key or changing its meaning requires a Keystone major release.

## Upstream registry

Frozen since 0.5.0. Structural validation:
`src/keystone_mcp/upstream_registry/validate.py`; load rules:
`src/keystone_mcp/upstream_registry/load.py`.

- Document shape: `schema_version: 1`, `entries:` (YAML or JSON; the same
  array may be supplied in `KEYSTONE_MCP_UPSTREAMS` when no registry file is
  loaded). Changes to the registry file are applied without a restart (since 0.6.0).
- Per-entry fields accepted by the loader and validator: `name`, `url`
  (required for `transport: http`), `namespace` (1–64 characters
  `A-Za-z0-9_-`, not starting or ending with `_` or `-`), `enabled`,
  `include_prefixes`, `exclude_prefixes`, `strip_prefix`, `tool_prefix`,
  `publish_resources`, `resource_include_prefixes`, `resource_exclude_prefixes`,
  `discovery_timeout_seconds`, `tool_timeout_seconds`, `route_mode` (`live` or
  `stub`, default `live`), `auth` (`bearer_env`, `identity_secret_env`,
  `identity_alg` with value `ES256`), `transport` (`http` default or `stdio`),
  and for `stdio`: `command`, `args`, `env`, `cwd`. Optional `limits`:
  `concurrency`, `rate`, `window`, `breaker_failures`,
  `breaker_recovery_seconds` (per-entry service protection; omitted means no
  limit).
- `auth.bearer_env` and `auth.identity_secret_env` name
  `KEYSTONE_MCP_UPSTREAM_*` variables (never secret values in the file).
- `name` and `namespace` must be unique across entries.
- A new optional field is not breaking. A new required field or a semantic
  change requires `schema_version: 2` and a Keystone major release.

## MCP surface

### Proxied upstream tools

Published names are `<namespace>_<tool>` after `strip_prefix` and `tool_prefix`
filtering. `inputSchema` is the upstream schema (plus
`KEYSTONE_MCP_PROXY_SCHEMA_PATCHES` when configured). Proxy responses pass the
upstream payload through unchanged unless
`KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=true`, in which case the client sees
`{state, tool, task_id, result}` (status envelope).

### Protocol pass-through

| Mechanism | Passes through |
|---|---|
| `tools/list`, `tools/call` | yes |
| `notifications/progress` (upstream → client) | yes, when the client sent a `progressToken` |
| `notifications/tools/list_changed` | yes, after catalog, policy or users-directory change |
| `notifications/cancelled` (client → upstream) | yes (client cancel or Keystone tool timeout) |
| `prompts/list`, `prompts/get` | yes |
| `notifications/prompts/list_changed` | yes |
| `resources/list`, `resources/read`, `resources/templates/list` | yes |
| `notifications/resources/list_changed` | yes |
| `resources/subscribe`, `notifications/resources/updated` | no |
| `elicitation/create` (upstream → user) | yes for HTTP upstreams when `KEYSTONE_MCP_PROXY_ELICITATION=true` (form mode; URL mode declined); not for stdio |
| `sampling/createMessage`, `roots/list` | no |
| `notifications/message` (upstream logs) | no |
| `completion/complete` | no |
| MCP tasks (`tasks/*`) | no |

Same rows apply to stdio upstreams except upstream→user elicitation (never
forwarded).

### Built-in tools

Published only when `KEYSTONE_MCP_RBAC_MODE=enforce` unless noted.

**Users directory** (`users_*`): `users_list` and `users_export` for every
configured directory; `users_export` is limited to full administrators and is
refused to service accounts. The export document carries
`format: keystone-person-export/1`; fields may be added in minor releases.
`users_add`, `users_update`,
`users_block`, `users_unblock`, `users_set_roles`, `users_grant_role`,
`users_revoke_role`, and `users_logout` require the `admin` capability.
`users_delete` requires the `delete` capability (built-in directory only at
0.6.0) and is limited to full administrators. Its first successful step returns
`state: "confirmation_required"` with a summary and one-time code; the second
step with a valid code returns `state: "done"`. Arguments and error codes match
[keystone-user-admin skill](../skills/keystone-user-admin/SKILL.md). The
`users_*` tools may return: `actor_email_required`, `bad_request`, `conflict`,
`forbidden`, `identity_binding_conflict`, `last_administrator`, `self_admin_mutation_forbidden`,
`service_error`, `service_timeout`, `service_unavailable`, `service_unconfigured`,
`user_not_found`, `validation_error`.

**Service accounts** (built-in directory with `service_accounts` capability):
`service_accounts_list`, `service_accounts_add`, `service_accounts_update`.
Error codes: `actor_email_required`, `bad_request`, `conflict`, `forbidden`,
`identity_binding_conflict`, `last_administrator`, `self_admin_mutation_forbidden`,
`service_error`, `service_timeout`, `service_unavailable`, `user_not_found`,
`validation_error`. Mutating tools answer `forbidden` to service accounts.

**API keys** (built-in directory with `api_keys` capability):
`api_keys_list`, `api_keys_revoke` always; `api_keys_issue` is **not**
published when `KEYSTONE_MCP_DEPLOYMENT_PROFILE=production` (issue keys with
`keystone-mcp keys` on the server instead). Error codes: `actor_email_required`,
`bad_request`, `conflict`, `forbidden`, `identity_binding_conflict`,
`last_administrator`, `self_admin_mutation_forbidden`, `service_error`, `service_timeout`,
`service_unavailable`, `user_not_found`, `validation_error`. Mutating tools
answer `forbidden` to service accounts.

**Policy administration** (`policy_*`): `policy_read`, `policy_catalog`,
`policy_validate`, `policy_role_set`, `policy_role_delete`, `policy_allow_add`,
`policy_allow_remove`, `policy_list_set`, `policy_rollback` (optional
`expected_hash`). Published when
`KEYSTONE_MCP_RBAC_MODE=enforce` and `KEYSTONE_MCP_POLICY_TOOLS` is not `off`;
mutations require `full` and a writable policy file. Namespace `policy` is
reserved in the upstream registry. Error codes:
`validation_error`, `role_not_found`, `role_in_use`, `policy_invalid`,
`unmatched_pattern`, `policy_invariant`, `self_lockout_forbidden`,
`policy_readonly`, `policy_conflict`, `nothing_to_rollback`, `forbidden`,
`service_unavailable`. See [policy-admin.md](policy-admin.md).

There are no built-in file-transfer tools (removed in 0.5.0).

`Pattern` on built-in routes is frozen as `SYNC` or `CONTINUATION`.

## Headers sent to upstream services

Frozen since 0.5.0.

| Header | Meaning |
|---|---|
| `X-Keystone-Subject` | Verified subject (`email` for people, `svc:<name>` for service accounts), lower-case email when applicable |
| `X-Keystone-Subject-Type` | `human` or `service` |
| `X-Author-Email` | Verified person email (lower-case); **deprecated (since 0.5.0, use X-Keystone-Identity)**; sent only for human subjects; removed in 2.0 |
| `traceparent` / `tracestate` | W3C trace context; sent when `KEYSTONE_MCP_OTEL_ENABLED=true` (and accepted from clients on inbound HTTP) |
| `Authorization: Bearer <value>` | When the registry entry sets `auth.bearer_env` and the named variable is non-empty (HTTP upstreams only) |
| `X-Keystone-Identity` | Signed JWT (`typ: keystone-identity+jwt`). **HS256** with the secret named by `auth.identity_secret_env` (per-upstream secret, at least 32 bytes), or **ES256** with `KEYSTONE_MCP_IDENTITY_SIGNING_KEY` when `auth.identity_alg: ES256`. **Audience** (`aud`) is the registry entry `name`. **Issuer** (`iss`) is `KEYSTONE_MCP_BASE_URL` without a trailing slash. **Expiry** (`exp`) is the tool-call timeout (seconds, rounded up) plus 60 seconds. **Roles** (`roles`) are those RBAC used to allow the call (empty when denied). Claims include `sub`, `sub_type`, `rbac`, optional `rbac_decision` (`allow`/`deny` when RBAC is active), `auth_method`, `interactive`, `task_id`, `mcp_method`, `mcp_target`, `iat`, `jti`, and for humans `email` when present; `client_id` when the OAuth client is known. ES256 JWKS may list up to two public keys during rotation (`KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS`). Stdio upstreams carry the same assertion in `params._meta["keystone-mcp/identity"]` instead of an HTTP header. |

## HTTP routes

Frozen since 0.5.0.

**Host and Origin** (`HostGuardMiddleware`): every route except `/healthz` and
`/readyz` checks `Host` and `Origin`. Allowed hosts are the host (and
optional port) of `KEYSTONE_MCP_BASE_URL`, its loopback aliases, and
`KEYSTONE_MCP_ALLOWED_HOSTS`. On internal endpoint paths (`KEYSTONE_MCP_METRICS_PATH`
when metrics are enabled, and `/internal/*` when internal endpoints are enabled),
an IP-literal `Host` is also accepted. Wrong `Host` → `421`; wrong `Origin` → `400`;
`Origin: null` is treated as absent.

| Route | Method | Notes |
|---|---|---|
| MCP endpoint | per `KEYSTONE_MCP_HTTP_PATH` (default `/`) | Streamable HTTP MCP |
| `/.well-known/oauth-authorization-server` | GET | OAuth metadata |
| `/.well-known/oauth-protected-resource` | GET | Protected resource metadata (+ MCP path variant) |
| `/.well-known/keystone-identity-jwks.json` | GET | ES256 JWKS when `KEYSTONE_MCP_IDENTITY_SIGNING_KEY` is set |
| `/authorize` | GET | Authorization endpoint |
| `/token` | POST | Token endpoint |
| `/register` | POST | Dynamic client registration when `KEYSTONE_MCP_OAUTH_DCR_ENABLED=true` |
| `/revoke` | POST | Token revocation (RFC 7009) |
| `/login` | GET, POST | Sign-in page |
| `/login/<provider>` | GET, POST | Sign-in page for one provider |
| `/login/redirect-not-allowed` | GET | Error page when the client's redirect host is not allowed |
| `/login/<provider>/callback` | GET | Redirect provider callback; Google uses `/login/google/callback` when the provider name is `google` |
| `/healthz` | GET | Liveness: `{"status": "ok"}`, always `200` |
| `/readyz` | GET | Readiness: `{"status": "ok"|"degraded"}`, `200` or `503`. Trusted internal callers also see `checks`, `upstreams`, `policy_content_hash`, and `policy_in_sync`. |
| `KEYSTONE_MCP_METRICS_PATH` | GET | Prometheus when `KEYSTONE_MCP_METRICS_ENABLED=true` |
| `/internal/live-published-names` | GET | When `KEYSTONE_MCP_INTERNAL_ENDPOINTS_ENABLED=true` |

HTML copy on sign-in, consent and error pages is not part of the contract.

## CLI

Frozen since 0.5.0. Exit codes are part of the contract; command output text is not.

| Command | Exit codes |
|---|---|
| `keystone-mcp catalog validate`, `keystone-mcp catalog diff` | `0` success; `1` validation error; `3` `--live-url` unreachable |
| `keystone-mcp catalog export` | `0` success; `1` validation error |
| `keystone-mcp upstream validate --path <file>` | `0` ok; `1` validation or I/O error |
| `keystone-mcp users grant-admin`, `users import`, `users admins`, `users block`, `users unblock`, `users logout`, `users export`, `users delete`, `users unbind-identity` | per `users/cli.py` (`0` success, non-zero documented failures; `users admins` and `users delete` on the last administrator exit `1`; `users delete` exits `2` when confirmation is refused, `3` when the person was removed but sessions were not revoked) |
| `keystone-mcp users db current` | `0` when the database revision matches this binary; `4` when the database is newer; `5` when it is older |
| `keystone-mcp users db downgrade --to <revision> [--yes]` | `0` on success; `1` usage; `2` when `--yes` is missing and stdin is not a terminal; `3` database or downgrade error |
| `keystone-mcp keys issue`, `keys list`, `keys revoke` | `0` on success, non-zero on failure |
| `keystone-mcp service-accounts add`, `service-accounts list`, `service-accounts update` | `0` on success, non-zero on failure |
| `keystone-mcp upstream validate` | `0` ok; `1` validation or I/O error |
| `keystone-mcp plugins list` | `0` on success, non-zero on failure |
| `keystone-mcp oauth register-client` | `0` registered or updated; `1` invalid arguments, redirect URI not allowed, or no Redis configured; `3` Redis unavailable |
| `keystone-mcp config check [--env-file PATH] [--strict] [--admins]` | `0` no errors; `1` errors (or warnings with `--strict`); `2` usage or `.env` load failure |
| `keystone-mcp serve` | runs until stopped; configuration errors refuse startup |
| `python -m keystone_mcp.server` | same entry point as `keystone-mcp serve` |
| `python -m keystone_mcp.healthcheck <path>` | `0` when the HTTP probe succeeds, non-zero otherwise |

Flags for `catalog` (`--policy`, `--snapshot`, `--live-file`, `--live-url`,
`--strict-unreachable`, `--tier`) and `users import` (`--from-url`, `--token`,
`--policy`, `--dry-run`) are frozen. `users grant-admin` accepts an
optional `--role <name>` (must grant full administration). `users admins`
accepts `--json`.

## Users directory database

Frozen since 0.5.0 for the built-in SQL schema (SQLite or Postgres URL in
`KEYSTONE_MCP_USERS_DB_URL`).

| Table | Purpose |
|---|---|
| `keystone_user` | People: `email` PK, `full_name`, `is_blocked`, `note`, `created_by`, `created_at`, `updated_at`; optional `idp_issuer`, `idp_subject`, `idp_bound_at` (0.6.0); unique `(idp_issuer, idp_subject)` when set |
| `keystone_user_role` | `id`, `email` FK, `role`, unique `(email, role)` |
| `keystone_service_account` | Service accounts: `name` PK, `description`, `is_blocked`, `created_by`, `created_at`, `updated_at` |
| `keystone_service_account_role` | `id`, `name` FK, `role`, unique `(name, role)` |
| `keystone_api_key` | Hashed API keys: `key_id`, `subject`, `secret_hash`, `label`, `created_by`, `created_at`, `expires_at`, `revoked_at`, `revoked_by` |
| `keystone_users_alembic_version` | Alembic revision tracking |

Upgrading to a new minor release runs migrations automatically at startup.
Downgrade is supported with `keystone-mcp users db downgrade` run by the newer
version; see [upgrading.md](upgrading.md). Tables belonging to other
applications in the same database are not modified.

## Redis

Keystone-MCP writes only under `KEYSTONE_MCP_REDIS_KEY_PREFIX` (default
`km:oauth:`), `KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX` (default `km:login:`),
`KEYSTONE_MCP_USERS_REDIS_REVISION_KEY` (default `km:users:revision`), and
`KEYSTONE_MCP_POLICY_REDIS_REVISION_KEY` (default `km:rbac:policy:revision`).
The layout under those prefixes is internal, but minor
version upgrades are expected to keep existing OAuth sessions and in-flight
login transactions valid. From 0.6.0, OAuth tokens are stored under their
SHA-256; upgrading moves legacy keys on first use. Rolling back to 0.5.x after
0.6.0 signs everyone out.

## Extension points

Frozen since 0.5.0.

| Mechanism | Contract |
|---|---|
| `LoginProvider` protocols (`RedirectLoginProvider`, `FormLoginProvider`) | Module `keystone_mcp.login.protocol`; see [Plugin API](#plugin-api) |
| `LoginIdentity` | `LoginIdentity` gained optional `key_id`, `key_expires_at`, `issuer`, `subject_id` in 0.6.0 (additive; providers that do not set them are unaffected) |
| `IdentityBindingDirectory` | Optional users-directory protocol (capability `identity_binding`) since 0.6.0 |
| `UserDeletionDirectory` | Optional users-directory protocol (capability `delete`) since 0.6.0 |
| `UserDirectory` and related protocols | Module `keystone_mcp.user_directory.protocol`; optional `ApiKeyIdIndex`, `ApiKeyStateReader` (since 0.6.0) |
| Entry point group `keystone_mcp.login_providers` | Built-in: `oidc`, `google`, `api_key` |
| Entry point group `keystone_mcp.user_directories` | Built-in: `local`, `http` |
| Pytest plugin `keystone_mcp.contract_tests` | Contract tests for providers and directories (`pytest -p keystone_mcp.contract_tests`, optional extra `contract-tests`) |

## Plugin API

Frozen since 0.6.0 for names listed here; login and user-directory **protocols** in
`keystone_mcp.login.protocol` and `keystone_mcp.user_directory.protocol` are frozen
since 0.5.0 (member names and signatures until 2.0).

**Frozen surface:** protocol classes above; `keystone_mcp.plugins.{PluginContext,
LoginProviderConfig, LoginProviderFactory, UserDirectoryFactory, PluginConflictError}`;
`keystone_mcp.user_directory.types` and `.errors`; `keystone_mcp.user_directory.normalize_email`;
base classes in `keystone_mcp.user_directory.base` and `keystone_mcp.login.base`;
`keystone_mcp.login.oidc.{OidcLoginProvider, OidcProviderConfig}` as the OIDC plugin base;
classes and fixtures in `keystone_mcp.contract_tests` (including `FakeTamper.unavailable`).

**Growth rule:** The 0.5 protocols never gain members before 2.0. A new capability
arrives as a new optional protocol (and, for directories, a new `capabilities` value);
Keystone uses it only when a plugin implements it. New dataclass fields always have
defaults. Base classes provide defaults for new optional protocols; inheriting them is
optional.

**Validation:** Keystone checks a plugin against the frozen 0.5 method list
(`PROTOCOL_MEMBERS_0_5`), not `isinstance`; startup errors name missing methods.

**Contract tests (since 0.6.0):** A test class must inherit the contract class for every
declared directory capability; availability tests require
`keystone_unavailable_directory_factory` (or
`@pytest.mark.keystone_contract_lenient(reason=…)` on the class). Other 0.5.0 contract
checks are unchanged; new checks ship in separate opt-in classes. Checks added in 0.6.0
live in opt-in `*Checks06` classes (see [plugins.md](plugins.md)); they join the main
contract classes in 2.0.

## Observability

Frozen since 0.5.0. Metric names and label keys (not log message text):

| Metric | Labels |
|---|---|
| `keystone_mcp_rbac_decisions_total` | `decision`, `reason`, `tool_family`, `operation` |
| `keystone_mcp_tool_call_attempts_total` | `tool_family`, `namespace`, `tool`, `auth_method`, `oauth_client_id` |
| `keystone_mcp_tool_invocations_total` | `tool_family`, `namespace`, `tool`, `auth_method`, `oauth_client_id`, `outcome` |
| `keystone_mcp_tool_invocation_seconds` | `tool_family`, `namespace`, `tool`, `auth_method`, `oauth_client_id`, `outcome` |
| `keystone_mcp_users_directory_response_issues_total` | `field`, `issue` |
| `keystone_mcp_rbac_directory_resolve_total` | `outcome` |
| `keystone_mcp_rbac_directory_resolve_seconds` | (histogram) |
| `keystone_mcp_rbac_policy_reload_total` | `success` |
| `keystone_mcp_rbac_policy_info` | `content_hash` |
| `keystone_mcp_rbac_policy_in_sync` | (gauge, no labels) |
| `keystone_mcp_rbac_policy_revision_checks_total` | `outcome` |
| `keystone_mcp_users_mutation_total` | `operation`, `outcome` |
| `keystone_mcp_policy_mutation_total` | `operation`, `outcome` |
| `keystone_mcp_admin_refusals_total` | `operation`, `reason` |
| `keystone_mcp_catalog_refresh_total` | `outcome` |
| `keystone_mcp_catalog_refresh_changes_total` | `direction` |
| `keystone_mcp_list_changed_sessions_total` | `kind` |
| `keystone_mcp_upstream_available` | `namespace` |
| `keystone_mcp_upstream_process_restarts_total` | `namespace` |
| `keystone_mcp_upstream_stderr_suppressed_total` | `namespace` |
| `keystone_mcp_upstream_items_rejected_total` | `namespace`, `kind`, `reason` |
| `keystone_mcp_upstream_input_rounds_exceeded_total` | `namespace` |
| `keystone_mcp_upstream_elicitations_total` | `namespace`, `action` |
| `keystone_mcp_upstream_limit_rejections_total` | `namespace`, `reason` |
| `keystone_mcp_upstream_circuit_state` | `namespace` |
| `keystone_mcp_upstream_inflight` | `namespace` |
| `keystone_mcp_upstream_registry_reload_total` | `outcome` |
| `keystone_mcp_upstream_registry_info` | `content_hash` |
| `keystone_mcp_oauth_client_registrations_total` | `outcome` |
| `keystone_mcp_oauth_client_evictions_total` | (counter, no labels) |
| `keystone_mcp_oauth_token_exchange_total` | `grant_type`, `outcome` |
| `keystone_mcp_login_identity_binding_total` | `outcome` |
| `keystone_mcp_oauth_token_keys_migrated_total` | `kind`, `direction` |
| `keystone_mcp_oauth_clients` | (gauge, no labels) |
| `keystone_mcp_api_key_verifications_total` | `outcome` |
| `keystone_mcp_api_key_cache_entries` | `cache` |
| `keystone_mcp_api_key_cache_evictions_total` | `cache` |
| `keystone_mcp_users_revision_bump_failed_total` | — |
| `keystone_mcp_throttle_backend_errors_total` | `kind` |
| `keystone_mcp_http_origin_null_total` | `route` |

Label value `unknown` is reserved for names that are not published.

Audit event types and field names (values are not frozen): optional `trace_id`
on audit payloads when tracing is enabled; `rbac_authz_decision`,
`rbac_users_mutation`, `rbac_policy_mutation`, `oauth_session` — see
[observability-rbac.md](observability-rbac.md) and `src/keystone_mcp/observability/audit.py`.
NDJSON access-log field names (including `trace_id` and `span_id` when tracing
is enabled) are in [observability-logging.md](observability-logging.md).
OpenTelemetry span names and attributes are not frozen — see [observability-tracing.md](observability-tracing.md).

## Container image and distribution

Frozen since 0.5.0.

| Artifact | Frozen name |
|---|---|
| Container image | `ghcr.io/keystone-codes/keystone-mcp:<version>` (multi-arch `linux/amd64`, `linux/arm64`; tag `latest` points at the highest released version) |
| Helm chart (OCI) | `oci://ghcr.io/keystone-codes/charts/keystone-mcp:<version>` (source tree: `charts/keystone-mcp`) |
| Container port | `8080` |
| Runtime user | uid/gid `10001` (`keystone`) |
| Writable volume | `/data` with default `KEYSTONE_MCP_USERS_DB_URL=sqlite:////data/keystone-users.db` in the image |
| Health check | `python -m keystone_mcp.healthcheck /readyz` |
| PyPI distribution | `keystone-mcp-gateway` |
| Python package | `keystone_mcp` |
| Console script | `keystone-mcp` |

## Not covered

Python API except the protocols above (including `RouterRegistry`, `Adapter`,
`Pattern`, `Settings`, and internal modules); all of `keystone_mcp.contrib` and
`KEYSTONE_MCP_CONTRIB_*`; log, startup error and HTML texts; Redis key layout
under the prefixes; the Helm chart values (until 1.0); files under `examples/`
and `docker-compose.demo.yml`;
behaviour of `KEYSTONE_MCP_DEPLOYMENT_PROFILE=local` beyond what
[environment.md](environment.md) documents; OpenTelemetry span names and
attributes when tracing is enabled.

## What counts as a breaking change

Removing or renaming anything listed in the sections above; changing a
default in a way that alters behaviour for an existing installation (except a
documented security fix, then noted under `### Security` and `### Migration` in
the changelog); adding a new required environment variable or registry field
without a default; changing a frozen `users_*` or `policy_*` error code, a CLI
exit code, or an HTTP status code on a frozen route; a database migration that
needs manual operator action.

## Deprecation rule

From 0.5.0 onward:

1. Deprecated items are listed under `### Deprecated` in [CHANGELOG.md](../CHANGELOG.md)
   and marked `deprecated (since X.Y, use …)` in this document.
2. They keep working and emit one startup warning (or the documented refusal
   for removed security-sensitive variables).
3. They remain for at least one minor release and are removed only in the next
   major Keystone-MCP version (2.0).
4. Removed environment variables are recorded in `REMOVED_VARIABLES` in
   `config.py`, [environment.md#removed-variables](environment.md#removed-variables),
   and `### Removed` in the changelog.

Enforced in CI by `tests/test_contract_freeze.py` against a baseline generated
from the `v0.5.0` tag.

## Supported versions

Until 1.0.0, only the latest released minor version receives security fixes.
After 1.0.0, only the latest minor release of the current major version does.
When 2.0 is released, this section states how long 1.x receives security fixes.
1.0.0 will be a release of an existing 0.x line that ran two weeks in production without breaking changes; it adds no features.
