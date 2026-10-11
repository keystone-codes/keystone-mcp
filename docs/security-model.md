# Security model

Keystone-MCP is the only public entry point of the application behind it.
Access is not one setting but three independent ones — who exists, how they
prove who they are, and what they may call — plus a profile switch that
decides which of them the server lets you get wrong. This page explains each,
what crosses the network, and what the `local` and `production` profiles
check at startup.

## Three things decide access

| Question | Where it lives | Who changes it |
|---|---|---|
| Who exists, and with which roles? | The users directory (built in) | An administrator, through `users_*` or the CLI |
| How do they prove it? | The sign-in method (Google or a DEV token) | The operator, via `KEYSTONE_MCP_ENABLED_LOGIN_METHODS` |
| What may they call? | The RBAC policy file | Whoever edits `KEYSTONE_MCP_RBAC_POLICY_PATH` |

They are independent: switching sign-in from DEV tokens to Google does not
touch anyone's roles, and editing the policy file does not touch who exists.
Example: Alice exists in the directory with role `analyst`; she signs in with
Google; the policy lets `analyst` call `reports_*` and nothing else.

### Who exists: the users directory

Keystone-MCP keeps its own list of people — email, roles, blocked or not. It
is built in by default, or an external HTTP service for forks (see
[environment.md#users-directory](environment.md#users-directory) for the
backend switch). **Sign-in works only for an email that
already exists in the users directory and is not blocked. Signing in never
creates a person** — someone with access has to add them first with
`users_add`, or they come from `KEYSTONE_MCP_SUPERADMIN_EMAIL` at the first
start. Details, including recovering a lost administrator account, are in
[users.md](users.md).

### How they prove it: the sign-in secret

- **Google** (`KEYSTONE_MCP_ENABLED_LOGIN_METHODS=google`) — the production
  method. The email Google verifies is looked up in the users directory,
  lower-cased first; an email can never carry different directory entries
  through different casing.
- **DEV token** (`KEYSTONE_MCP_DEV_TOKENS`) — a shared secret for testing
  roles without wiring up Google. A holder signs in as *any* email that
  exists in the directory, so it is accepted only under the `local` profile
  (below); `production` refuses a non-empty value outright.
- **API key through an external service** (`KEYSTONE_MCP_AUTH_SERVICE_URL`) —
  deprecated, moving into the users directory in 0.4.1.

### What they may call: the policy file

[`KEYSTONE_MCP_RBAC_POLICY_PATH`](rbac-policy-format.md) lists roles and the
tool-name patterns each one may call. Everything not matched by a pattern is
refused. A role can be granted to a person only if that name already exists
in the file (`unknown role: <name>` otherwise); the one name the directory
always accepts, file or no file, is `administrator` — reserved, and the
system refuses to block or demote the last active administrator, or let one
remove their own `administrator` role.

## A client application is not a person

Registering an OAuth client (`POST /register`, dynamic client registration —
DCR) records a *program* — Cursor, Claude Desktop, a script — not a person.
It grants no access to any tool by itself: a registered client still has to
send a real person through `/login` before it can call anything, and that
person still has to exist in the users directory. An operator who registers
every client by hand can turn DCR off entirely with
`KEYSTONE_MCP_OAUTH_DCR_ENABLED=false`; see [Registering a client
manually](environment.md#registering-a-client-manually). Client records are
not kept forever — `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` caps how many can be
live at once, and each one ages out with the token lifetimes below.

Because any client can register with any return address, Keystone-MCP shows
a **consent screen** (`GET /login?txn=…`) before anything else happens on
`/authorize`: which application is asking (self-reported `client_name` — a
hint, not proof) and, in bold, where the result is sent (the `redirect_uri`
host). Nothing — neither the token form nor the Google button — proceeds
without an explicit action here, on every `/authorize`, not just the first
time a client is used. This closes the attack where an attacker registers
their own client with their own `redirect_uri`, and sends a victim a bare
link straight into `/authorize`: without a screen in between, a victim
already signed in to Google would sail through and hand the attacker their
authorization code. The handoff to Google is itself gated by a CSRF cookie
bound to the browser that saw the consent screen, so the same link cannot be
replayed by an attacker who only has the URL. That cookie (`km_login_csrf`,
or `__Host-km_login_csrf` when `KEYSTONE_MCP_BASE_URL` is `https`) is minted
fresh on every render of the consent screen — a value the request already
carried is never reused, so a cookie an attacker planted (over a plain-http
same-host endpoint, or a sibling subdomain without the `__Host-` prefix's
restrictions) is never handed back as the CSRF secret. The `__Host-` prefix
itself is enforced by the browser, not just by name: it refuses to store the
cookie at all unless it is `Secure`, path-scoped to `/` and carries no
`Domain` attribute, which is what keeps a sibling subdomain from setting it
in the first place.

An operator who knows which clients are legitimate can remove the decision
from the person entirely: `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`
restricts `redirect_uri` to a fixed list of hostnames. A bare host entry
matches `https` for that host and `http` only when the host is also
loopback; a native app's custom URI scheme (e.g. `cursor://...`) matches
only an explicit `scheme://host` entry. With the list set, registration,
`/authorize`, and token exchange (both an authorization code and a refresh
token) all refuse a client whose `redirect_uri` is not allowed — including a
client that registered before the list existed, so it cannot keep refreshing
forever on an allowance that no longer holds. See
[`KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`](environment.md) for the exact
matching rules.

## Trust zones

![Clients reach only Keystone-MCP on the public network. Service MCP ports, Redis, and databases stay on a private network with no published port.](network.svg)

The network is a separate cut from the application: the public side is given
one port, and every other port is not on it. The users directory is built
into Keystone-MCP itself by default, so it needs no port of its own; with
the external HTTP backend selected instead (see
[environment.md#users-directory](environment.md#users-directory)) it is one
more private-network service.

| Zone | Who | Responsibility |
|---|---|---|
| Public | MCP clients (Cursor, Claude Desktop, …) | OAuth to Keystone-MCP only |
| Keystone-MCP | This process | Identity, RBAC, routing, audit |
| Private | Upstream MCP services, Redis, the users directory's database (and the external users service, if `USERS_BACKEND=http`) | Business data; no public ports |

## What a service behind Keystone-MCP receives

Every proxied call carries `X-Author-Email` — the verified email of the
signed-in person, lower-cased. It carries no roles: RBAC is decided on
Keystone-MCP before the call is forwarded, not re-checked by the upstream.
By itself, that header only proves a sender knows the right string; an
upstream should trust it only on a network Keystone-MCP alone controls. An
upstream registry entry can additionally set `auth.bearer_env` to a variable
holding a token; Keystone-MCP then sends `Authorization: Bearer <value>` on
every discovery and proxied call to that entry, so the upstream can check
that header *first*, before trusting `X-Author-Email` at all — see
[Connecting services](connecting-services.md#authenticating-keystone-mcp-to-your-service).
Without `auth.bearer_env` configured, network isolation is the only control:
plan the upstream's address with `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP`
and `KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE` in mind (below). The proxy
itself never follows a redirect an upstream sends back.

## RBAC modes

| `KEYSTONE_MCP_RBAC_MODE` | Tool calls | Catalog |
|---|---|---|
| `off` | No RBAC deny | All published tools visible |
| `observe` | Allowed; denials logged | Filtered as in `enforce` |
| `enforce` | Denied when the policy or the user's roles say so | Filtered per role |

Production profile requires **`enforce`** (below). Built-in `users_*` admin
tools are published **only in `enforce`**; in `off` and `observe` they do
not exist at all, and startup logs a warning saying so instead of leaving
the impression that user administration is reachable without authorization.

## Local and production profiles

`KEYSTONE_MCP_DEPLOYMENT_PROFILE` (`local` | `production`, default
**`production`**) decides which of the rules below `validate_settings`
checks at startup. The full table, including the warnings that only log
instead of refusing, is
[environment.md#deployment-profile](environment.md#deployment-profile); one
row per rule here:

| Rule | Profile | Meaning |
|---|---|---|
| L1 | `local` | `KEYSTONE_MCP_BASE_URL` must be loopback — a local server is never reachable from outside this machine. |
| P1 | `production` | `KEYSTONE_MCP_DEV_TOKENS` must be empty; startup refuses otherwise. |
| P2 | `production` | `KEYSTONE_MCP_RBAC_MODE` must be `enforce`. |
| P3 | `production` | `api_key` sign-in needs `KEYSTONE_MCP_AUTH_SERVICE_URL` and `_TOKEN` both set. |
| P4 | `production` | `KEYSTONE_MCP_BASE_URL` may not be a public `http` address — terminate TLS first. |
| W1 | `production` | `KEYSTONE_MCP_BASE_URL` using `http` on a *non-public* host (for example, a private address behind a reverse proxy that terminates TLS) only warns at startup — P4 already refuses a public `http` address, so this covers the one case P4 lets through. |
| W2/W3 | `production` | `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP` / `_EGRESS_ALLOW_PRIVATE` only warn at startup; they do not refuse, because a deployment whose upstreams are genuinely all-private needs them. |
| W4 | `local` | `KEYSTONE_MCP_RBAC_MODE=enforce` with a non-empty `KEYSTONE_MCP_DEV_TOKENS` only warns — this is the intended way to test roles locally without Google. |

Outside the profile check, `KEYSTONE_MCP_AUTH_SERVICE_URL` set without
`_TOKEN` is always a startup error, in either profile. The built-in users
directory accepts a SQLite file under `local` only; under `production` it
needs PostgreSQL and startup refuses a SQLite URL (rule P5 in
[environment.md](environment.md#deployment-profile)). An external users
service (`KEYSTONE_MCP_USERS_BACKEND=http`) is not affected by this rule.

## Sessions, codes and tokens

OAuth clients, authorization codes, and refresh tokens live in **Redis**
(`KEYSTONE_MCP_REDIS_URL`); there is no in-memory fallback, so every replica
sees the same state. An authorization code is single-use — read and deleted
atomically, so two concurrent exchanges cannot both succeed. Refreshing a
token rotates it: a new refresh token is written and the old one is deleted,
but kept resolvable (as a thin marker, not valid for exchange) for a short
grace period so a second, in-flight request against the just-rotated token
does not read nothing and silently fall back to a weaker identity. Every
record expires: an access token after `KEYSTONE_MCP_TOKEN_TTL`, a refresh
token after `KEYSTONE_MCP_REFRESH_TOKEN_TTL` of idleness, and a client record
after the longer of the two plus a day — see
[environment.md#server](environment.md#server) for the exact variables.

An access token is bound to the resource (RFC 8707) named in the
`/authorize` request behind it, with the resource URI normalized before
comparison; refreshing keeps that same binding instead of dropping it.
`KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR=true` refuses any token that names
no resource at all, including one issued before this binding existed.

## What is protected by default

- Every HTTP route — every OAuth endpoint, discovery metadata, and `/mcp`
  itself — refuses a request whose `Host` header (and, if present and not
  `null`, `Origin`) is not on an allowlist built from `KEYSTONE_MCP_BASE_URL` plus
  `KEYSTONE_MCP_ALLOWED_HOSTS` (`HostGuardMiddleware`,
  `src/keystone_mcp/http/host_guard.py`). Without this, a page on a hostname
  an attacker controls can rebind that hostname's DNS to `127.0.0.1` (or any
  address this process is reachable on) after the page has loaded, and have
  the page's own JavaScript carry on issuing requests the browser still
  addresses with `Host: <attacker's hostname>` — reaching a loopback-bound
  server from inside the victim's own browser, past network-level isolation,
  and (with DCR enabled) completing the whole OAuth flow: register a client,
  `/authorize`, `POST /login` with a DEV token, `/token`, then call any
  published tool. `/healthz`/`/readyz` are exempt — a container healthcheck
  or a Kubernetes probe reaches them by an address (`127.0.0.1`, or a pod IP
  assigned at pod start) that cannot be enumerated ahead of time, and both
  answer with only a coarse status and no secret. See
  [`KEYSTONE_MCP_ALLOWED_HOSTS`](environment.md) for the exact matching
  rules.
- `/metrics` and `/internal/*` answer only a caller whose source address
  matches `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`, and refuse outright any
  request that carries an `X-Forwarded-For` header at all — a value here
  would mean the "source address" is whatever a possibly-untrusted proxy
  reported, not a real network fact
  (`src/keystone_mcp/server.py::_reject_untrusted_internal_caller`).
- Logs never show a `Bearer` token, a password, a Redis URL's embedded
  credentials, or an email address in the clear
  (`KEYSTONE_MCP_LOG_REDACT=true`, the default).
- RBAC audit requires `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` to be set the
  moment audit is on; without it, subject identifiers in audit records would
  be guessable from an email and not actually pseudonymous.
- Sign-in attempts are rate-limited per IP and, for failures, per email
  (`KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX` / `_EMAIL_MAX`); `/authorize` and
  `/token` share a separate IP budget
  (`KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX`).
- An upstream address is checked before it is used: `https` is required
  unless `KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true`, userinfo
  (`user:pass@host`) in the URL is refused, and a private or loopback host
  needs both that flag and `KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE=true`
  (`src/keystone_mcp/upstream_registry/validate.py::validate_upstream_url`).
- Every HTML response from the login page sends `X-Frame-Options: DENY`, a
  `Content-Security-Policy` of `default-src 'none'; frame-ancestors 'none'`,
  `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff` — the
  page cannot be framed, cannot run injected scripts, and never leaks the
  sign-in transaction id through a `Referer` header.
- The container image runs as a non-root user (`Dockerfile`).

## Known limits

- The tool-call and login throttles are counted **per process**, not per
  cluster: behind a load balancer with several replicas, a single identity's
  effective budget multiplies by the replica count. See
  [environment.md#server](environment.md#server) for the per-process
  throttle note.
- There is no way to revoke every session a person holds in one action.
  Blocking them in the users directory takes effect on their **next call**
  (the directory is re-checked every time), but an access token already
  issued keeps working until it expires on its own.
- Production sign-in is Google only, up to 0.5; a general OIDC provider is
  on the roadmap with no date yet.
- `HostGuardMiddleware`'s allowlist does not exempt `/metrics`: unlike
  `/healthz`/`/readyz`, a Prometheus scraper reaching it by a pod IP (common
  in Kubernetes) needs that IP added to `KEYSTONE_MCP_ALLOWED_HOSTS` — not
  generally possible for an IP assigned at pod start. A scrape reaching this
  process through a stable name (a Service, or a sidecar on `localhost`)
  already resolves to an allowed host and needs nothing extra; a scrape
  reaching it directly by pod IP today will need an operator decision this
  card does not make.

## Checklist by profile

**Local** — a developer's own machine:

- [ ] `KEYSTONE_MCP_DEPLOYMENT_PROFILE=local`.
- [ ] `KEYSTONE_MCP_BASE_URL` is loopback.
- [ ] `KEYSTONE_MCP_SUPERADMIN_EMAIL` set; that person signed in once.
- [ ] `KEYSTONE_MCP_RBAC_MODE=enforce` if you are testing roles, `off` if not.
- [ ] Never exposed beyond loopback while `KEYSTONE_MCP_DEV_TOKENS` is set.

**Production** — see [production-checklist.md](production-checklist.md) for
the full list; in short:

- [ ] `KEYSTONE_MCP_DEPLOYMENT_PROFILE=production` (the default).
- [ ] `KEYSTONE_MCP_BASE_URL` is `https`; TLS terminates at a reverse proxy.
- [ ] `KEYSTONE_MCP_RBAC_MODE=enforce`; the policy file matches live tool names.
- [ ] The users directory runs on PostgreSQL and is backed up.
- [ ] A decision on DCR is made: left on, or off with clients registered by hand.
- [ ] Startup warnings (W1-W3) were read and are understood, not just silenced.

## Related docs

- [Production checklist](production-checklist.md)
- [Environment variables](environment.md)
- [Users](users.md)
- [RBAC policy format](rbac-policy-format.md)
- [Connecting services](connecting-services.md)
