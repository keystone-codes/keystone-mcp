# Environment variables

Every variable here is a public contract; see [compatibility.md](compatibility.md).

Every setting is one `KEYSTONE_MCP_*` environment variable with a documented
default (`src/keystone_mcp/config.py`). Copy [`.env.example`](../.env.example)
to `.env` and fill in the secrets. Do not commit `.env`.

Redis is required. The users directory is built in; the first administrator
is created by `KEYSTONE_MCP_SUPERADMIN_EMAIL`. See [users.md](users.md).

## Deployment profile

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_DEPLOYMENT_PROFILE` | `production` | `local` or `production`. Decides which rules below `validate_settings` checks at startup. |

`local` is your machine: `KEYSTONE_MCP_BASE_URL` must be a loopback address,
and DEV tokens (`KEYSTONE_MCP_DEV_TOKENS`) are allowed under any
`KEYSTONE_MCP_RBAC_MODE`. `production` (the default) is a public host: RBAC
must be `enforce`, DEV tokens are refused outright, and API-key sign-in for
people needs the built-in users directory (Postgres) unless only machines
sign in.

An unset `KEYSTONE_MCP_DEPLOYMENT_PROFILE` resolves to `production`, so an
existing deployment that never set this variable is validated as
`production` from this release on (see Migration in the changelog).

| Rule | Profile | Refuses at startup when | Fix |
|---|---|---|---|
| L1 | `local` | `KEYSTONE_MCP_BASE_URL` host is not loopback (`localhost`, `*.localhost`, or a loopback IP). | Point `KEYSTONE_MCP_BASE_URL` at a loopback address, or switch to `production`. |
| P1 | `production` | `KEYSTONE_MCP_DEV_TOKENS` is non-empty. | Clear `KEYSTONE_MCP_DEV_TOKENS`, or switch to `local`. |
| P2 | `production` | `KEYSTONE_MCP_RBAC_MODE` is not `enforce`. | Set `KEYSTONE_MCP_RBAC_MODE=enforce`, or switch to `local`. |
| P3 | `production` | `api_key` is enabled while `KEYSTONE_MCP_USERS_BACKEND=http`, or while an interactive provider (Google/OIDC) is also configured. | Use `KEYSTONE_MCP_USERS_BACKEND=local` with Postgres for API keys, or remove `api_key` / use only machine Bearer keys. |
| P4 | `production` | `KEYSTONE_MCP_BASE_URL` uses `http` and its host is publicly reachable — including a legacy decimal/hex IPv4 literal (`http://134744072/` is `http://8.8.8.8/`) and an internal-looking name such as `*.svc.cluster.local`/`*.internal` (a DNS suffix is not a trust boundary, so these are not treated as private). | Terminate TLS and use `https` (a TLS-terminating proxy or sidecar in front, for a closed-cluster install too), or point `KEYSTONE_MCP_BASE_URL` at a private host. |
| P5 | `production` | `KEYSTONE_MCP_USERS_BACKEND=local` (the default) and `KEYSTONE_MCP_USERS_DB_URL` is empty or a `sqlite` URL. | Point `KEYSTONE_MCP_USERS_DB_URL` at Postgres (`postgresql+psycopg://user:password@host:5432/db`), or switch to `local`. |

Users directory store: `local` — SQLite allowed; `production` — Postgres
required, SQLite refused (P5). SQLite is one file per replica: two replicas
each write their own copy and roles drift apart, and the file is lost with the
container unless a volume happens to be mounted on it. The rule only applies
to the built-in (`local`) users backend; `KEYSTONE_MCP_USERS_BACKEND=http`
manages its own storage and is unaffected.

`local` has no equivalent of P2-P5: a loopback-only server already cannot be
reached from outside this machine. Two further rules are warnings — logged by
`server.main` after startup, not refusals:

| Warning | Profile | Logged when |
|---|---|---|
| W1 | `production` | `KEYSTONE_MCP_BASE_URL` uses `http` on a non-public host (a private network behind a trusted reverse proxy). |
| W2 | `production` | `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true`. |
| W3 | `production` | `KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE=true`. |
| W4 | `local` | `KEYSTONE_MCP_RBAC_MODE=enforce` and `KEYSTONE_MCP_DEV_TOKENS` is non-empty: a DEV token then signs any directory member in, including administrators. |
| W5 | `local` | `KEYSTONE_MCP_HOST` is unspecified (`0.0.0.0`, `::`) and `KEYSTONE_MCP_DEV_TOKENS` is non-empty. Not a refusal — the Docker demo's own container legitimately binds `0.0.0.0` internally, relying on its port mapping to restrict reachability — but anyone who *can* reach the port signs in as any directory member. |
| W20 | `production` | `KEYSTONE_MCP_USERS_BACKEND=http`, `KEYSTONE_MCP_USERS_SERVICE_URL` uses `http` on a non-loopback host, and `KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP` is not set. |
| W21 | `production` | `KEYSTONE_MCP_OAUTH_DCR_ENABLED=true` and `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` (and custom-scheme entries) are empty: any site can register an OAuth client. List the redirect hosts of the clients you use. |
| W7 | both | RBAC is `enforce`, `KEYSTONE_MCP_POLICY_TOOLS=full` (the default) and the policy file is not writable (e.g. mounted `:ro`). Not a refusal — `policy_read`/`policy_validate` still work — but every mutating `policy_*` call refuses with `policy_readonly` until the mount is read-write or this replica is switched to `KEYSTONE_MCP_POLICY_TOOLS=read-only`. |

## Where settings come from

Both entry points — `python -m keystone_mcp.server` and the `keystone-mcp`
CLI — load a `.env`-style file as their very first step, before any setting
is read, then build `Settings` from the process environment only (the file
itself is never consulted again). Order of precedence:

1. A variable already set in the process environment (shell export, systemd
   `Environment=`, `docker run -e`, `uv run --env-file`, …) always wins.
2. Otherwise, the value comes from the loaded file, if the name appears there.
3. Otherwise, the documented default below applies.

**Which file is loaded** — `KEYSTONE_MCP_ENV_FILE` decides, read from the
process environment (so it cannot itself be set from inside the file it
names):

- Not set: `.env` in the current working directory. No file there is not an
  error — loading is simply skipped.
- Set to a non-empty path (relative paths resolve against the current working
  directory): that file is loaded; if it does not exist, startup fails with a
  clear error naming the path.
- Set to the empty string: loading is disabled outright.

No other location is searched — not the package directory, not the home
directory, not `/etc`. Under systemd the working directory is usually `/`,
where there is no `.env`; use `EnvironmentFile=` in the unit, or point
`KEYSTONE_MCP_ENV_FILE` at an explicit path.

**File format:**

- Blank lines and lines starting with `#` are skipped.
- An optional `export ` prefix is stripped.
- Each remaining line is `KEY=VALUE`, split on the first `=`; a line with no
  `=` fails startup, naming the file and line number.
- Only names matching `KEYSTONE_MCP_*` are loaded; anything else (e.g.
  `COMPOSE_PROJECT_NAME`) is silently ignored.
- A value wrapped in a matching pair of quotes (`'…'` or `"…"`) has the quotes
  stripped and the content taken verbatim — no escape sequences, no `${VAR}`
  substitution.
- In an unquoted value, ` #` (a space then `#`) starts a trailing comment; a
  `#` with no preceding space is part of the value, so a password containing
  `#` does not need quoting.

Example `systemd` unit using `EnvironmentFile=` (equivalent to `.env` in the
working directory, but explicit and independent of it):

```ini
[Service]
WorkingDirectory=/opt/keystone-mcp
EnvironmentFile=/etc/keystone-mcp/keystone-mcp.env
ExecStart=/opt/keystone-mcp/.venv/bin/python -m keystone_mcp.server
```

Or, keeping `.env` loading but pointing it at a fixed path regardless of the
working directory:

```ini
[Service]
Environment=KEYSTONE_MCP_ENV_FILE=/etc/keystone-mcp/keystone-mcp.env
ExecStart=/opt/keystone-mcp/.venv/bin/python -m keystone_mcp.server
```

## Server

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_BASE_URL` | `http://localhost:8080` | Public base URL the client reaches the server on; drives the OAuth issuer, discovery metadata, and the RFC 8707 resource indicator. |
| `KEYSTONE_MCP_HTTP_PATH` | `/` | Streamable HTTP route path. |
| `KEYSTONE_MCP_HOST` | `127.0.0.1` | Bind address. |
| `KEYSTONE_MCP_PORT` | `8080` | Bind port. |
| `KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` | `25` | After SIGTERM, how long (0–3600) the HTTP server waits for in-flight requests to finish before closing (`timeout_graceful_shutdown`). Give the container at least 35 s to stop (`terminationGracePeriodSeconds`, `stop_grace_period`, `docker stop -t`). |
| `KEYSTONE_MCP_ALLOWED_HOSTS` | `` (empty) | Comma-separated extra names `HostGuardMiddleware` accepts on the `Host`/`Origin` headers, beyond `KEYSTONE_MCP_BASE_URL`'s own host (any port) and, when that host is loopback, `localhost`/`127.0.0.1`/`[::1]` on `KEYSTONE_MCP_BASE_URL`'s port. Each entry is a bare host (matches any port — e.g. a load balancer's hostname, whose port Keystone cannot predict) or `host:port` (that exact pair only). A request whose `Host` is not on the effective list is refused with `421`; an `Origin`, when present and not `null`, is checked the same way and refused with `400`. `/healthz` and `/readyz` are exempt entirely (a container healthcheck or a Kubernetes probe reaches them by an IP — `127.0.0.1`, or a pod IP assigned at pod start — that cannot be enumerated ahead of time). `/metrics` and `/internal/*` are **not** exempt: a scraper or `catalog --live-url` that addresses this process as `127.0.0.1:8080`, a Service name or a pod IP needs that exact name here (a pod IP cannot be listed in advance). See [`docs/security-model.md`](security-model.md) for the DNS-rebinding scenario this closes. |
| `KEYSTONE_MCP_LOG_LEVEL` | `INFO` | Root log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |
| `KEYSTONE_MCP_LOG_FORMAT` | `json` | `json` (NDJSON to stderr) or `text` for human-readable lines. |
| `KEYSTONE_MCP_LOG_REDACT` | `true` | Redact tokens, credentials, Redis URLs with passwords, and emails in log output. |
| `KEYSTONE_MCP_LOG_ACCESS_ENABLED` | `true` | Emit one structured access line per HTTP request that passes the Host/Origin check (a request refused with `421`/`400` is logged only as an app warning) via `keystone_mcp.access` (uvicorn access log is off). |
| `KEYSTONE_MCP_LOG_REQUEST_ID_HEADER` | `X-Request-ID` | Incoming correlation header; a UUID is generated when absent. |
| `KEYSTONE_MCP_LOG_REQUEST_ID_RESPONSE` | `true` | Echo the request id on the response when not already set. |
| `KEYSTONE_MCP_TOKEN_TTL` | `86400` | Access-token lifetime, seconds. |
| `KEYSTONE_MCP_AUTH_CODE_TTL` | `600` | Authorization-code lifetime, seconds. |
| `KEYSTONE_MCP_REFRESH_TOKEN_TTL` | `2592000` (30d) | Idle lifetime of a refresh token before re-login is required. |
| `KEYSTONE_MCP_THROTTLE_MAX` | `120` | Max requests per identity within the throttle window (`tools/call`, `prompts/get`, `resources/read`, and `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`); `0` disables. |
| `KEYSTONE_MCP_THROTTLE_WINDOW` | `60` | Throttle sliding-window length, seconds. |
| `KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX` | `30` | Max `POST /login`, `POST /login/google` and `POST /register` attempts per client IP in the login throttle window; `0` disables the IP limit. |
| `KEYSTONE_MCP_LOGIN_THROTTLE_EMAIL_MAX` | `10` | Max failed `POST /login` attempts per email in the window; successful logins do not count; `0` disables the email limit. |
| `KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW` | `300` | Login throttle sliding-window length, seconds. |
| `KEYSTONE_MCP_OAUTH_DCR_ENABLED` | `true` | Dynamic client registration (RFC 7591). `false` removes `POST /register` and the `registration_endpoint` entry from `/.well-known/oauth-authorization-server`; register clients manually instead (see [Registering a client manually](#registering-a-client-manually) below). The `/register` IP throttle (`KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX`) is unaffected. When enabled, `POST /register` accepts at most 16 KB of JSON; `client_name` ≤ 100 characters; ≤ 10 `redirect_uris` of ≤ 2 KB each; unlisted RFC 7591 fields are dropped. A client that never completes sign-in expires after 24 hours. |
| `KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX` | `120` | Max `GET`/`POST /authorize` and `POST /token` requests per client IP in the login throttle window; `0` disables. In-process: each replica counts separately. |
| `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` | `10000` | Soft cap on the number of live (non-expired) registered OAuth clients. Past the cap, the oldest client that never completed a sign-in is evicted to admit the new one; if every client has been used, registration is refused with `invalid_client_metadata`. `0` means unlimited; a negative value is a startup error. Checked against the shared Redis client count, so the cap holds across replicas, though two replicas registering at the same instant can both pass the check (soft limit). |
| `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` | `` (empty) | Comma-separated bare hostnames (no scheme, no port, no path — e.g. `claude.ai,localhost`), or an IPv6 literal (`::1`, or bracketed, `[::1]`); lower-cased, exact match only, no subdomains or wildcards. Empty means no restriction, the 0.3.1 behaviour. When set, `POST /register` refuses a client whose `redirect_uris` include a disallowed combination (`invalid_redirect_uri`) — including `redirect_uris: null`/empty, which is refused rather than treated as "no redirect_uris to check" — and both `/authorize` and `POST /token` (authorization-code and refresh-token exchange) refuse one whose client is not allowed, even for a client registered before the restriction was turned on or tightened. `/authorize`'s refusal does **not** redirect to the client's (disallowed) `redirect_uri`, under any error condition — including a client-side validation error such as an unregistered `scope`, which the MCP SDK itself would otherwise redirect to that `redirect_uri` before Keystone's own check ever ran: it 302s to this server's own `/login/redirect-not-allowed`, which renders a 400 page, so the browser never visits the disallowed host. A bare host entry matches `https` for that host, and `http` only when the host is also loopback (`localhost`/`127.0.0.1`/`::1`) — `http://claude.ai/...` is refused even if `claude.ai` is listed. A custom (non-http(s)) URI scheme, e.g. a native app's `cursor://...`, is matched only against an explicit `scheme://host` entry in the same list (e.g. `cursor://anysphere.cursor-retrieval`); `http://`/`https://` are refused in that form (they are already covered by the bare-host rule, and allowing them here would bypass the loopback-only rule for `http`). An entry containing `/`, or `:` that is not part of a valid IPv6 literal or a `scheme://host` form, is a startup error (`ConfigError`), as is a malformed `scheme://host` entry. |

`/authorize` and `/token` share one IP budget, separate from the
`/login`/`/register` one above, and the same `KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW`.
Code exchange and token refresh for web-based clients (for example Claude
running in a browser) are issued from the client vendor's own servers, so many
end users can arrive from a handful of shared IPs; raise this limit at a large
organization.

Running one process on `localhost` with no proxy in front, these limits work
as the table says. Put a reverse proxy in front, or run more than one
replica, and both the IP seen by the login limiter and the effective size of
every limit change — see
[Rate limits, reverse proxies and replicas](#rate-limits-reverse-proxies-and-replicas)
below.

## Rate limits, reverse proxies and replicas

This section is about the limits in the table above, plus what changes once
Keystone-MCP sits behind a reverse proxy or runs as more than one replica.

### Limits and presets

| Limit | Counts per | Variables | Default | `0` means |
|---|---|---|---|---|
| Tool calls and MCP lists | person (verified email) | `KEYSTONE_MCP_THROTTLE_MAX` / `_WINDOW` | `120` / `60` s | no limit |
| Login and registration attempts | client IP | `KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX` / `KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW` | `30` / `300` s | no IP limit |
| Failed login attempts | email | `KEYSTONE_MCP_LOGIN_THROTTLE_EMAIL_MAX` / same window | `10` | no email limit |
| `/authorize` and `/token` | client IP | `KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX` / same window as login | `120` | no limit |

`.env.example` ships four presets for the first three rows (uncomment one
block; the `/authorize`/`/token` limit is not part of a preset, set it
separately if you need to):

| Preset | When | Tool calls | Login per IP |
|---|---|---|---|
| `local-dev` | one developer, agents calling tools in a loop | `1000` / `60` s | defaults |
| `small-team` | up to about 20 people (matches the defaults) | `120` / `60` s | `30` / `300` s |
| `busy-gateway` | many agents per person, or many people behind one NAT | `300` / `60` s | `60` / `300` s |
| `strict-edge` | public host, few people, cautious | `30` / `60` s | defaults |

### Behind a reverse proxy

A client behind an unconfigured reverse proxy looks like one address to the
login limiter — one real client failing a login locks out every other client
sharing that proxy, because all their attempts count against the same IP
budget.

Why: the login and OAuth-token limiters key on `request.client.host`, the TCP
peer uvicorn sees. IPv6 addresses are grouped by `/64` (IPv4-mapped IPv6
addresses count as their IPv4); counters are per process, not shared across
replicas. Keystone-MCP runs on uvicorn with `proxy_headers=True`
(uvicorn's own default), which only trusts `X-Forwarded-For` from peers
listed in `FORWARDED_ALLOW_IPS` — a plain uvicorn/environment variable, no
`KEYSTONE_MCP_` prefix, default `127.0.0.1`. Outside that allowlist the
header is ignored and `request.client.host` is whoever uvicorn's TCP
connection came from: the proxy itself.

| Deployment shape | `FORWARDED_ALLOW_IPS` |
|---|---|
| Proxy and Keystone-MCP on the same host, no container | nothing to set, the peer already is `127.0.0.1` |
| Proxy on the host, Keystone-MCP in a Docker container | the container's gateway address, e.g. `docker network inspect <network> -f '{{(index .IPAM.Config 0).Gateway}}'`, or the network's CIDR |
| Proxy on another machine, or a Kubernetes ingress | that machine's address, or the pod network CIDR |

Set `FORWARDED_ALLOW_IPS=*` only when nothing except the proxy can reach
Keystone-MCP directly — otherwise anyone can set their own `X-Forwarded-For`
and dodge the IP limit entirely.

The proxy closest to Keystone-MCP must **replace** this header with the real
client address, not append to one a client already sent (nginx:
`proxy_set_header X-Forwarded-For $remote_addr;` when it is the first hop,
`$proxy_add_x_forwarded_for` when it sits behind another trusted proxy).

`/metrics` and the other internal endpoints refuse any request that carries
`X-Forwarded-For` at all, regardless of `FORWARDED_ALLOW_IPS` — scrape them
directly, never through the public proxy (see [Internal endpoints](#internal-endpoints)).

To check it worked: fail a login twice from two different machines through
the proxy and look at the access log (`"stream":"access"`, field `client_ip`
— see [observability-logging.md](observability-logging.md)); it should show
each machine's own address, not the proxy's.

### More than one replica

Keystone-MCP keeps some state in the process and some in Redis. Only the
Redis-backed state is shared across replicas:

| In each process | Shared in Redis |
|---|---|
| Tool-call throttle (`KEYSTONE_MCP_THROTTLE_MAX`) | OAuth clients, codes and tokens |
| Login/registration and `/authorize`/`/token` IP throttles | Pending logins |
| Users-directory allow/deny cache | Users-directory revision marker (`km:users:revision`) invalidates every replica's cache at once |
| Circuit breaker for the users directory | — |
| Live upstream tool catalog | — |

Consequences:

- A single person's effective budget can reach up to N × the configured
  limit with N replicas behind a load balancer, for every limit in the table
  above — the balancer spreads their calls across processes that each keep
  their own counters.
- A block or role change takes effect on every replica immediately: the
  revision marker invalidates the cache everywhere, and a critical tool
  (`is_critical_tool`) always bypasses the allow-cache and re-checks on every
  call.
- The live catalog (which upstream tools are published) can differ between
  replicas until each has completed its own refresh tick
  (`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`).
- The RBAC policy file is re-read independently by each replica; a `SIGHUP`
  must reach every replica, not just one.

What to do: either divide the limit you want by the replica count
(`KEYSTONE_MCP_THROTTLE_MAX = <target> / N`) or pin each client to one
replica with sticky sessions on the load balancer. A shared, cluster-wide
limit in Redis is on the roadmap, no date yet.

The users directory itself (`KEYSTONE_MCP_USERS_DB_URL`) is a single
database, not per-process state, so it is already shared across replicas
without any of the above caveats. With PostgreSQL, migrations at startup take
a transactional advisory lock, so several replicas starting at once do not
race each other; with SQLite, only one process should ever hold the file. The `production`
profile refuses a SQLite users database at startup (rule P5); under `local`,
point `KEYSTONE_MCP_USERS_DB_URL` at PostgreSQL yourself before running more
than one replica.

## Redis

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_REDIS_URL` | `""` (required) | Shared Redis for OAuth clients/tokens and login-pending state. |
| `KEYSTONE_MCP_REDIS_KEY_PREFIX` | `km:oauth:` | Key namespace for OAuth data. |
| `KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX` | `km:login:` | Key namespace for pending login transactions and one-time codes. |
| `KEYSTONE_MCP_LOGIN_PENDING_TXN_TTL` | `600` | Pending login transaction TTL, seconds. |

Under `KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX`, namespaced keys include
`refresh_auth:<refresh token>` (JSON session marker for a refresh token; fields
are only ever added, an older Keystone ignores unknown fields), `code:<…>`,
`txn:<…>`, and `login_attempt:<…>`.

There is no in-memory fallback. OAuth sessions are always in Redis.

**Record lifetimes.** Every OAuth record in Redis carries a TTL, so Redis
does not grow without bound:

- Access token: `KEYSTONE_MCP_TOKEN_TTL`.
- Refresh token: `KEYSTONE_MCP_REFRESH_TOKEN_TTL`, renewed on every rotation
  (`/token` with `grant_type=refresh_token`).
- Client: 24 hours until the first successful sign-in (authorization-code
  exchange or refresh); after that, `max(KEYSTONE_MCP_REFRESH_TOKEN_TTL,
  KEYSTONE_MCP_TOKEN_TTL)` plus one day, renewed on every token issued under
  it. A client idle longer than its lifetime is deleted and the connector
  registers again on its next connection.

Records written before this release have no TTL; one is attached the first
time the record is read (see the Migration note in `CHANGELOG.md`).

**Per-subject session index** (under `KEYSTONE_MCP_REDIS_KEY_PREFIX`, default
`km:oauth:`):

| Key pattern | Type | Meaning | TTL |
|---|---|---|---|
| `subject:<sub>` | SET | Members `at:<token>` and `rt:<token>` for that subject (`sub` is the normalized email) | `max(REFRESH_TOKEN_TTL, TOKEN_TTL)` plus one day, renewed when a token is added |
| `subject_nbf:<sub>` | STRING | Unix seconds: tokens issued before this moment are invalid | Same as the subject set |
| `client_index` | ZSET | Live registered client ids (score = expiry time) | n/a (members expire with clients) |
| `client_unused` | ZSET | Client ids that never completed sign-in (score = registration time) | n/a (entries older than 24 h are pruned) |

Tokens issued before an upgrade are added to the subject set on first use
(lazy migration). A block or `users_logout` still invalidates them via
`subject_nbf` even if they were never read after the upgrade. Redis **6.0+**
is required (`SET … KEEPTTL` during lazy migration). The demo stack uses
Redis 7.

A password is part of the URL (`redis://:password@host:6379/0`; with an ACL
user, `redis://user:password@host:6379/0`). Reserved characters in the
username and password are percent-encoded. `./setup.sh` writes
`KEYSTONE_MCP_REDIS_URL` and starts the `keystone-redis` container only when
you chose local Redis and `127.0.0.1:6379` is free.

Why: [ADR 0004](adr/0004-redis-is-required.md).

## Login

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_DEV_TOKENS` | `""` | Local profile only; comma-separated DEV tokens for the sign-in page. In production issue API keys from the users directory instead. |
| `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH` | `""` | Path to a YAML file listing sign-in providers (Google, Okta, any OIDC issuer, API key). When set, it replaces the legacy variables below. See [login-providers.md](login-providers.md). |
| `KEYSTONE_MCP_PRIMARY_LOGIN_METHOD` | `api_key` | Deprecated since 0.5.0 (kept until the next major version); see [login-providers.md](login-providers.md). Login method shown first; must be in `ENABLED_LOGIN_METHODS`. |
| `KEYSTONE_MCP_ENABLED_LOGIN_METHODS` | `api_key` | Deprecated since 0.5.0 (kept until the next major version); see [login-providers.md](login-providers.md). Comma-separated set of login methods offered when no providers file is configured. |
| `KEYSTONE_MCP_LOGIN_DEFAULT_LANG` | `en` | Login-page fallback language when no explicit choice, `km_lang` cookie, or `Accept-Language` match applies: `ar`, `en`, `he`, or `ru`. Language order on the page: `?lang=` override, then the `km_lang` cookie (set only after an explicit switch), then the browser's `Accept-Language`, then this setting. |
| `KEYSTONE_MCP_LOGIN_BRAND` | `Keystone-MCP` | Name shown in the sign-in page header, title, and footer (1–64 characters, no logo image). |

Sign-in, consent, and error pages are rendered by a built-in template with no
external fonts, scripts, or remote images; a custom logo file is not supported.

### Google (legacy env vars)

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_GOOGLE_CLIENT_ID` | `""` | Deprecated since 0.5.0 (kept until the next major version); see [login-providers.md](login-providers.md). Required when `google` is an enabled login method and no providers file is set. |
| `KEYSTONE_MCP_GOOGLE_CLIENT_SECRET` | `""` | Deprecated since 0.5.0 (kept until the next major version); see [login-providers.md](login-providers.md). Required when `google` is an enabled login method and no providers file is set. |
| `KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN` | `""` | Deprecated since 0.5.0 (kept until the next major version); see [login-providers.md](login-providers.md). Optional Google Workspace domain restriction. |

A client cannot supply its own email. The address comes from the verified
login. Redirect sign-in also requires the address to already exist in the users
directory and not be blocked. Provider setup (Google, Okta, Entra ID, Keycloak)
is [login-providers.md](login-providers.md). The Google redirect URI remains
`{KEYSTONE_MCP_BASE_URL}/login/google/callback`.

### Registering a client manually

With `KEYSTONE_MCP_OAUTH_DCR_ENABLED=false`, `POST /register` does not exist
and the server no longer accepts self-registration. The operator registers
each OAuth client directly in the shared OAuth store (`KEYSTONE_MCP_REDIS_URL`)
by running this from the installation directory, with the server's own
environment loaded (so it points at the same Redis):

```bash
uv run python - <<'PY'
import asyncio
from mcp.shared.auth import OAuthClientInformationFull
from keystone_mcp.config import Settings
from keystone_mcp.auth.oauth_store import build_oauth_store

async def main() -> None:
    store = build_oauth_store(Settings())
    client = OAuthClientInformationFull(
        client_id="claude-desktop",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="Claude",
    )
    await store.put_client(client)
    await store.aclose()

asyncio.run(main())
PY
```

The redirect URI above is Claude's own connector callback (example only);
substitute the redirect URI of whatever client you are registering.
`client_id` and `redirect_uris` are the only fields a connecting client
strictly needs to match; adjust `client_name` freely.

A manually registered client has no special lifetime: it expires on the same
schedule as a self-registered one (`KEYSTONE_MCP_REFRESH_TOKEN_TTL` /
`KEYSTONE_MCP_TOKEN_TTL`, whichever is longer, plus one day), and that
lifetime is renewed on every token issuance. If nobody has used the client
for longer than that, re-run the script with the same `client_id` — writing
the client again is idempotent and simply restores it. A dedicated CLI
(`keystone-mcp oauth register-client`) is planned for a later release; until
then this script is the supported path.

## RBAC, audit and metrics

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_RBAC_MODE` | `off` | `off` — no role check. `observe` — evaluate and audit, still allow the call. `enforce` — deny the call and hide the tool from the catalog. |
| `KEYSTONE_MCP_RBAC_POLICY_PATH` | `""` | Path to the RBAC policy YAML; required when RBAC is `observe` or `enforce`. |
| `KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT` | `""` | Optional catalog snapshot YAML (active/reserved/wip tool names) used to validate the policy. |
| `KEYSTONE_MCP_RBAC_AUDIT_ENABLED` | `true` | Structured audit log events. |
| `KEYSTONE_MCP_RBAC_AUDIT_LIST_TOOLS_SAMPLE_RATE` | `0.1` | Sample rate for successful `list_tools` audit events (denials are never sampled). |
| `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` | `""` | Required when RBAC and audit are both on; pseudonymizes subject identifiers in audit records. |
| `KEYSTONE_MCP_POLICY_TOOLS` | `full` | `full` — the `policy_*` tools may read and change the policy file. `read-only` — they may only read and validate (use this on every replica but one when the policy file is not on a shared volume). `off` — no `policy_*` tools are published. |
| `KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR` | `false` | Refuse an access token that names no RFC 8707 resource at all. |
| `KEYSTONE_MCP_METRICS_ENABLED` | `false` | Expose the Prometheus metrics endpoint. |
| `KEYSTONE_MCP_METRICS_PATH` | `/metrics` | Metrics route path. |
| `KEYSTONE_MCP_METRICS_TOOL_NAME` | `full` | `full` — per-tool label on call metrics; `coarse` — `tool` label is the namespace prefix only (lower cardinality). |
| `KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT` | `50` | Distinct `oauth_client_id` label values kept per process (first-seen wins); further client ids are reported as `other`. `0` reports every client as `other`. Must be `>= 0`. |

The policy file format is [rbac-policy-format.md](rbac-policy-format.md).
Audit fields and example alerts are [observability-rbac.md](observability-rbac.md).

`SIGHUP` queues an immediate policy reload on the refresh loop (`kill -HUP <pid>`).
The same loop also reloads the policy when the file bytes change on disk.
A file that fails validation is rejected and the last good policy stays.
The signal handler is installed when the mode is `observe` or `enforce`.

## Users directory

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_USERS_BACKEND` | `local` | `local`, `http`, or the name of an installed directory plugin. |
| `KEYSTONE_MCP_USERS_BACKEND_CONFIG` | `""` | Optional path to a YAML file with options for a directory plugin (ignored for built-in `local` / `http`). |
| `KEYSTONE_MCP_USERS_DB_URL` | `sqlite:///./keystone-users.db` | Database for the built-in users directory. A SQLite file path (`sqlite:///relative/path.db` or `sqlite:////absolute/path.db`), or a PostgreSQL URL using the `psycopg` driver (`postgresql+psycopg://user:pass@host:5432/db`). Migrated automatically at startup. |
| `KEYSTONE_MCP_SUPERADMIN_EMAIL` | `""` | Created with the `administrator` role on every start, if not already present. A block set on this user is never lifted by this seeding; see [users.md](users.md). |
| `KEYSTONE_MCP_USERS_SERVICE_URL` | `""` | Only with `KEYSTONE_MCP_USERS_BACKEND=http`. Required when Google login or RBAC is enabled. |
| `KEYSTONE_MCP_USERS_SERVICE_TOKEN` | `""` | Only with `KEYSTONE_MCP_USERS_BACKEND=http`. Bearer token for the users directory. Same secret as that service's own token. |
| `KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS` | `3.0` | Only with `KEYSTONE_MCP_USERS_BACKEND=http`. Per-request timeout. |
| `KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP` | `false` | Silences the production warning about an `http://` `KEYSTONE_MCP_USERS_SERVICE_URL`. |
| `KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS` | `60` | Cache TTL for an allow decision. Resolver caches are capped (10 000 verified keys, 10 000 denials, 50 000 subject resolutions); the built-in directory’s active `key_id` index is refreshed at least this often. |
| `KEYSTONE_MCP_USERS_CACHE_DENY_TTL_SECONDS` | `30` | Cache TTL for a deny decision (same cache caps as above). |
| `KEYSTONE_MCP_USERS_REDIS_REVISION_KEY` | `km:users:revision` | Shared Redis key that invalidates the directory cache across replicas. |
| `KEYSTONE_MCP_USERS_CIRCUIT_FAILURE_THRESHOLD` | `5` | Consecutive failures before the directory circuit breaker opens. |
| `KEYSTONE_MCP_USERS_CIRCUIT_RECOVERY_SECONDS` | `30` | Time before the circuit breaker retries after opening. |

Who is created first, and how later people are added, is [users.md](users.md).

## Upstreams

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_UPSTREAMS_PATH` | `""` | Path to a YAML or JSON upstream registry (`schema_version: 1`, `entries: [...]`). When non-empty and the file exists, this wins over `KEYSTONE_MCP_UPSTREAMS`. |
| `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP` | `false` | Allow `http://` upstream URLs. Needed for services on an internal network; the production profile logs a warning. |
| `KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE` | `false` | Allow upstream hosts treated as private: `localhost`, `*.localhost`, `*.local` (including `*.svc.cluster.local`), `*.internal`, and loopback, link-local, private or reserved IP literals (a non-canonical IP literal such as `2130706433` is refused outright). Both this and `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP` must be `true` for such hosts. |
| `KEYSTONE_MCP_UPSTREAMS` | `""` | Fallback: the registry entries as one JSON array, used when no registry file is loaded (`KEYSTONE_MCP_UPSTREAMS_PATH` wins when both are set). Fields: `name`, `url`, `namespace`, `enabled`, `include_prefixes`, `exclude_prefixes`, `strip_prefix`, `tool_prefix`, `discovery_timeout_seconds`, `tool_timeout_seconds`, `route_mode`, `auth` (`{"bearer_env": "VAR_NAME", "identity_secret_env": "VAR_NAME", "identity_alg": "ES256"}`, see below). |
| `KEYSTONE_MCP_IDENTITY_SIGNING_KEY` | `` (empty) | Optional EC P-256 private key in PEM form for ES256 identity assertions (`auth.identity_alg: ES256`); publishes `/.well-known/keystone-identity-jwks.json`. Startup refuses a non-P-256 or malformed value. Generate with `openssl ecparam -name prime256v1 -genkey -noout \| openssl pkcs8 -topk8 -nocrypt`. See the prose below. |
| `KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES` | `3` | Retries per upstream at startup; upstreams are discovered in parallel. |
| `KEYSTONE_MCP_UPSTREAM_DISCOVERY_TIMEOUT` | `10.0` | Per-attempt discovery timeout, seconds. |
| `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL` | `false` | When `true`, refuse startup when any configured upstream is unreachable (process exits with code `1` after `/healthz` has started answering). When `false` (default), an unreachable upstream is logged and retried on every refresh tick -- unless `KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=0`, in which case it is logged but never retried (there is no background task to retry it). In both cases `/readyz` answers `503` until background startup (discovery and policy load) finishes; with `false`, a single bad upstream does not block readiness after that. With `true`, `/readyz` also fails while any upstream remains unavailable after startup. |
| `KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS` | `300` | How often the running process re-reads upstream tool lists and RBAC policy files; `0` disables the background refresh task entirely. With it disabled, an upstream that is unreachable at startup stays unreachable for the life of the process -- it is never retried. |
| `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS` | `180.0` | Default max wait for a proxied tool call. |
| `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` | `""` | JSON object of per-published-tool timeout overrides in seconds. |
| `KEYSTONE_MCP_PROXY_SCHEMA_PATCHES` | `""` | Path to a JSON file patching properties onto a proxied tool's `inputSchema`. See `src/keystone_mcp/router/proxy_schema.py`. |
| `KEYSTONE_MCP_PROXY_STATUS_ENVELOPE` | `false` | `true` wraps proxied answers in `{state, tool, task_id, result}` and maps a `status` field of `error`/`refused`/`accepted` to an error, a rate-limit error, or a pending task (0.3.x behaviour). At `false` (default), the upstream's response — every content block, `structuredContent`, `isError` — is passed back to the client unchanged. |
| `KEYSTONE_MCP_PROXY_ELICITATION` | `true` | When `true` (default), HTTP upstreams may ask the connected MCP client form-mode elicitation questions (prefixed with `[namespace]`); URL-mode asks are declined. Stdio upstreams and discovery sessions never receive an elicitation handler. `false` disables forwarding entirely (the upstream sees no client elicitation capability). |

A registry entry's `auth.bearer_env` names an environment variable holding a
bearer token; Keystone-MCP sends it to that upstream as `Authorization: Bearer
<value>` on discovery and every proxied call, and refuses to start if the
named variable is unset or empty. The name must start with
`KEYSTONE_MCP_UPSTREAM_` (e.g. `KEYSTONE_MCP_UPSTREAM_<NAMESPACE>_TOKEN`) and
must not be one of the `KEYSTONE_MCP_UPSTREAM_*` settings listed in the table
above (`ALLOW_INSECURE_HTTP`, `EGRESS_ALLOW_PRIVATE`, `DISCOVERY_RETRIES`,
`DISCOVERY_TIMEOUT`, `REQUIRE_ALL`, `TOOL_TIMEOUT_SECONDS`,
`TOOL_TIMEOUTS`); registry validation refuses any other name, so an entry can
never be pointed at an unrelated secret such as
`KEYSTONE_MCP_GOOGLE_CLIENT_SECRET`.

`KEYSTONE_MCP_IDENTITY_SIGNING_KEY` holds an optional EC P-256 private key in
PEM form (multi-line value or `\n` escapes in one line). When set, upstream
entries may use `auth.identity_alg: ES256` instead of
`auth.identity_secret_env`: Keystone-MCP signs `X-Keystone-Identity` with
ES256 and publishes the matching public key at
`/.well-known/keystone-identity-jwks.json`. Empty means ES256 is unavailable.
Startup refuses a value that is not a valid P-256 PEM (never logs the key
itself). Generate one with
`openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`.
Rotation is replace the key and restart Keystone-MCP; assertions live only
minutes, so the outage window is short.

A registry entry's `auth.identity_secret_env` names a second, independent
environment variable: the HS256 secret Keystone-MCP signs the
`X-Keystone-Identity` assertion with for calls to that upstream (see
[connecting-services.md](connecting-services.md)). Same name rule as
`auth.bearer_env` above (must start with `KEYSTONE_MCP_UPSTREAM_`, must not
name one of Keystone's own `KEYSTONE_MCP_UPSTREAM_*` settings, and must not be
the same variable as that entry's `auth.bearer_env`); recommended shape
`KEYSTONE_MCP_UPSTREAM_<NAMESPACE>_IDENTITY_SECRET`. Keystone-MCP refuses to
start if the named variable is unset, empty, or shorter than 32 bytes (UTF-8)
— generate one with `openssl rand -base64 48`. An entry with no
`auth.identity_secret_env` only ever gets the unsigned, deprecated
`X-Author-Email` header (the `production` profile logs a warning per such
entry). Rotation is a Keystone-MCP restart with the new value: during the
rotation window, have the upstream service accept both the old and the new
secret so a call signed just before the restart still verifies.

A registry entry's `transport` is `http` (the default) or `stdio`. A
`stdio` entry runs as a local process instead of a network call and adds
four fields in place of `url`:

- `command` — the executable to run: a name resolved from `PATH`, or an
  absolute path. Required; never passed through a shell, so `~` and `$VAR`
  are not expanded.
- `args` — a list of command-line argument strings. Defaults to `[]`.
- `env` — which keystone-mcp environment variables the process receives,
  and under what name. Two equivalent forms: a mapping
  `{CHILD_NAME: KEYSTONE_MCP_VARIABLE_NAME}`, or the shorthand list
  `[NAME, ...]` (short for `{NAME: NAME}`). The value is always a
  *variable name*, never the secret itself — same rule as `auth.bearer_env`
  above, including the `KEYSTONE_MCP_UPSTREAM_` prefix requirement.
  Startup refuses to run if a named variable is not set at all (an empty
  value is accepted). The process otherwise receives none of
  keystone-mcp's own environment, only a minimal safe set
  (`HOME`/`LOGNAME`/`PATH`/`SHELL`/`TERM`/`USER` on Linux and macOS) plus
  whatever `env` names.
- `cwd` — the process's working directory. Optional; must be an existing
  directory when set.

`url` and `auth.bearer_env` are not allowed on a `stdio` entry: there is no
HTTP request to send a bearer token on. `auth.identity_secret_env` is still
allowed on a `stdio` entry — the signed identity assertion for stdio calls
travels in the request `_meta` instead of a header (Y09). Startup also
refuses to run if `command` cannot be found or is not executable.
`keystone-mcp upstream validate` checks only the registry's structure — it
does not require the command, the directory, or the named environment
variables to actually exist on the machine it runs on. Keystone-MCP
supervises the process once started: a crash or an unresponsive process is
restarted with a backoff that doubles from one second up to one minute,
resetting after a run stays healthy for a minute.

How a service is mounted, filtered and discovered is [facade.md](facade.md).

## Internal endpoints

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS` | `127.0.0.1/32,::1/128` | Comma-separated networks allowed to reach `/metrics` and `/internal/*`. These routes carry no credential. |
| `KEYSTONE_MCP_INTERNAL_ENDPOINTS_ENABLED` | `false` | Enables the live-published-tool-names introspection route. |

On `/metrics` and `/internal/*`, `HostGuardMiddleware` also accepts a `Host` header whose host part is an IPv4 or IPv6 literal (any port). A hostname still must appear on the effective allowlist. Source-address checks above are unchanged.

## Removed variables

Keystone-MCP refuses to start, or logs a warning, when one of these is still set.

- `KEYSTONE_MCP_RBAC_ENABLED` — removed in 0.5.0. Use `KEYSTONE_MCP_RBAC_MODE`. Startup is refused while it is set.
- `KEYSTONE_MCP_DET_INTERNAL_URL` — removed in 0.5.0. Nothing replaces it. A warning is logged while it is set.
- `KEYSTONE_MCP_FILE_API_URL` — removed in 0.5.0; startup is refused while it is set. File transfer is an upstream service, see [connecting-services.md](connecting-services.md).
- `KEYSTONE_MCP_WEBHOOK_BASE_URL` — removed in 0.5.0. A warning is logged while it is set. Use `KEYSTONE_MCP_CONTRIB_WEBHOOK_*`, see [contrib/adapters.md](contrib/adapters.md).
- `KEYSTONE_MCP_WEBHOOK_CLIENT` — removed in 0.5.0. A warning is logged while it is set. Use `KEYSTONE_MCP_CONTRIB_WEBHOOK_*`, see [contrib/adapters.md](contrib/adapters.md).
- `KEYSTONE_MCP_WEBHOOK_PROJECT` — removed in 0.5.0. A warning is logged while it is set. Use `KEYSTONE_MCP_CONTRIB_WEBHOOK_*`, see [contrib/adapters.md](contrib/adapters.md).
- `KEYSTONE_MCP_WEBHOOK_API_TOKEN` — removed in 0.5.0. A warning is logged while it is set. Use `KEYSTONE_MCP_CONTRIB_WEBHOOK_*`, see [contrib/adapters.md](contrib/adapters.md).
- `KEYSTONE_MCP_LONG_POLL` — removed in 0.5.0. A warning is logged while it is set. Use `KEYSTONE_MCP_CONTRIB_WEBHOOK_*`, see [contrib/adapters.md](contrib/adapters.md).
- `KEYSTONE_MCP_AUTH_SERVICE_URL` — removed in 0.5.0. API keys are issued and checked by the users directory; see [users.md](users.md). Startup is refused while it is set.
- `KEYSTONE_MCP_AUTH_SERVICE_TOKEN` — removed in 0.5.0. API keys are issued and checked by the users directory; see [users.md](users.md). Startup is refused while it is set.

## Docker

The [Dockerfile](../Dockerfile) is a multi-stage build: dependencies are installed
with [uv](https://docs.astral.sh/uv/) from `uv.lock` (`uv sync --frozen`), then
copied into a `python:3.12-slim` runtime. The container runs as the
unprivileged user `keystone` (uid/gid `10001`, fixed so a mounted volume's
host-side ownership is predictable; override with `--build-arg APP_UID=... --build-arg APP_GID=...`
at build time). `/app` (code and the virtualenv) stays read-only; `/data` is
declared as a `VOLUME` and owned by `keystone` for writable state. The image
sets `KEYSTONE_MCP_USERS_DB_URL=sqlite:////data/keystone-users.db` (see the
"Users directory" table above) so the built-in user directory's default
SQLite file lands in that writable volume — see [users.md](users.md) for
the directory itself. The image defines a `HEALTHCHECK` that runs
`python -m keystone_mcp.healthcheck` against `GET /readyz` — readiness, not
just liveness; the probe loads `.env` (or `KEYSTONE_MCP_ENV_FILE`) and uses
`KEYSTONE_MCP_HOST`/`KEYSTONE_MCP_PORT` for the URL — see
[observability-logging.md](observability-logging.md#readiness) for what it
checks. While background startup (upstream discovery and policy load) is still
running, `/readyz` returns `503` and the container may show `starting` or
`unhealthy` until discovery finishes — Docker does not restart the container
for that alone. There is no `curl` in the runtime image. Use `docker run --init` (or
Compose `init: true`) when stdio upstreams run in the same container so
orphaned child processes are reaped; after SIGTERM allow at least 35 s to
stop (`docker stop -t 35`, `stop_grace_period: 35s`) because
`KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` defaults to 25.

```bash
docker build -t keystone-mcp .
docker run -d --init -p 8080:8080 --env-file .env keystone-mcp
```

When mounting a host directory at `/data` instead of a named volume, grant
write access first: `sudo chown 10001:10001 ./data` (a named or anonymous
volume inherits the image's `/data` ownership automatically on first use).

Published images: `ghcr.io/keystone-codes/keystone-mcp`, for `linux/amd64` and
`linux/arm64`. The release workflow starts the `linux/amd64` build against
Redis and checks it over HTTP (`scripts/smoke_image.sh`) before publishing
either platform.
A three-container demo is [docker-compose.demo.yml](../docker-compose.demo.yml).
Inside a container set `KEYSTONE_MCP_HOST=0.0.0.0` (the image default and the
demo Compose file) and point `KEYSTONE_MCP_REDIS_URL` at the Compose service
name (`redis://redis:6379/0`).
