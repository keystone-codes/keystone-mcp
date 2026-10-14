# Production checklist

Use before pointing a public hostname (for example `mcp.example.com`) at
Keystone-MCP.

- [ ] `KEYSTONE_MCP_DEPLOYMENT_PROFILE=production` (the default; set it
      explicitly anyway, see [environment.md](environment.md#deployment-profile)).
- [ ] Run `keystone-mcp config check` and fix every warning you do not accept.

## Network and URL

- [ ] `KEYSTONE_MCP_BASE_URL` is the HTTPS origin clients use — scheme and
      host only, no path (the MCP route is `KEYSTONE_MCP_HTTP_PATH`).
- [ ] TLS terminates at a reverse proxy; upstream MCP ports are not published.
- [ ] Upstreams reachable only on a private network; they trust `X-Author-Email` only there.
- [ ] `FORWARDED_ALLOW_IPS` matches your reverse proxy (see
      [environment.md](environment.md#behind-a-reverse-proxy)).
- [ ] Every name a request can arrive under besides `KEYSTONE_MCP_BASE_URL`'s
      host — a load balancer's own hostname, the address a Prometheus
      scraper uses for `/metrics` — is listed in
      `KEYSTONE_MCP_ALLOWED_HOSTS` (otherwise `421`).

## Authentication

- [ ] Google OAuth redirect URI registered: `{BASE_URL}/login/google/callback`.
- [ ] Startup refuses DEV tokens in production (`KEYSTONE_MCP_DEPLOYMENT_PROFILE=production` always rejects a non-empty `KEYSTONE_MCP_DEV_TOKENS`).
- [ ] API keys are issued from the server (`keystone-mcp keys issue`); the `api_keys_issue` tool is not published in production.
- [ ] Service accounts that call MCP over HTTP use Bearer API keys (`Authorization: Bearer ksk_…`), not a person's OAuth access token.
- [ ] Set `KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS=2592000` (30 days) so a person disabled at the identity provider loses access within that time.
- [ ] A decision was made on dynamic client registration: left on (`KEYSTONE_MCP_OAUTH_DCR_ENABLED=true`, the default) or off with every client registered by hand (see [environment.md](environment.md#registering-a-client-manually)).
- [ ] If only specific client applications are expected, `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` lists their hosts.
- [ ] If people sign in through a single identity provider, set `KEYSTONE_MCP_LOGIN_IDENTITY_BINDING=bind`.

## RBAC and users

- [ ] `KEYSTONE_MCP_RBAC_MODE=enforce`.
- [ ] `KEYSTONE_MCP_RBAC_POLICY_PATH` loaded and matches live tool names.
- [ ] `KEYSTONE_MCP_USERS_DB_URL` points at PostgreSQL (`postgresql+psycopg://…`); the database is backed up (startup refuses a SQLite URL in this profile, see [environment.md](environment.md#deployment-profile)).
- [ ] `KEYSTONE_MCP_SUPERADMIN_EMAIL` set; that person signed in at least once.

## Redis and secrets

- [ ] `KEYSTONE_MCP_REDIS_URL` reachable only from Keystone-MCP; password or TLS if required.
- [ ] `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` set when audit is on.
- [ ] Secrets only in env/secret store, not in git.

## Observability

- [ ] `/readyz` used for load balancer/orchestrator readiness; `/healthz` for liveness
      only (`/healthz` opens after migrations; readiness waits on `/readyz` — see
      [observability-logging.md](observability-logging.md#readiness)).
- [ ] `/metrics` not exposed to the internet (`KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`).
- [ ] Audit log destination configured if `KEYSTONE_MCP_RBAC_AUDIT_ENABLED=true`.
- [ ] `KEYSTONE_MCP_LOG_FORMAT=json` and logs collected from stderr (see [observability-logging.md](observability-logging.md)).
- [ ] `KEYSTONE_MCP_LOG_REDACT=true` in production.
- [ ] Smoke: `jq -c 'select(.stream=="access")'` (or `grep '"stream":"access"'`) shows paths without query strings; `grep 'rbac audit'` still emits; no `Bearer` tokens in recent lines.

## Smoke after deploy

- [ ] `GET /healthz` → 200 soon after the process starts (port open after migrations).
- [ ] `GET /readyz` → 200 `{"status":"ok"}` once background startup, Redis, the RBAC
      policy, and the users database are up.
- [ ] OAuth login for an existing user; `list_tools` reflects role policy.
- [ ] One proxied tool call succeeds; upstream sees expected `X-Author-Email`.

## Deploy

- [ ] `keystone-mcp config check` reports no `ERROR` lines for the target environment.

Follow [paths/production-docker.md](paths/production-docker.md) for Docker
(the main path), or [deploy.md](deploy.md) for a host with systemd and
`./scripts/deploy.sh`. Keep secrets and host-specific runbooks outside this
repository.
