# Deploy Keystone-MCP with Docker

What you get: Keystone-MCP behind TLS on your own domain, interactive sign-in
through a providers file (Google or any OIDC issuer), a Postgres users
directory, and your own services on a private network nothing public can
reach. API keys remain the path for machines. About an hour, most of it
waiting on DNS.

## What you need

- A Linux server with Docker and Compose v2 (`docker compose version`).
- 2 vCPU / 2 GB RAM is enough for a small team; add resources per upstream
  service you run alongside it.
- A DNS name pointed at the server, with port 443 open.
- A Google Cloud project you can create an OAuth client in.

## 1. Get the files

```bash
git clone https://github.com/keystone-codes/keystone-mcp.git
mkdir -p /srv/keystone
cp -r keystone-mcp/examples/production/* /srv/keystone/
cp keystone-mcp/.env.example /srv/keystone/.env
cd /srv/keystone
```

Five files, each doing one job:

| File | What it does |
|---|---|
| `docker-compose.yml` | Keystone-MCP, Redis, and Postgres. Pinned image tag, loopback-only port, `init: true`, `stop_grace_period: 35s`. |
| `.env` | Every setting Keystone-MCP reads (copied from the repository's `.env.example`). |
| `login-providers.yaml` | Sign-in providers (Google, OIDC, optional API key). Mounted read-only. |
| `policy/rbac-policy.yaml` | Who may call which tools. The `policy/` directory is mounted read-write so `policy_*` tools can update the file. |
| `upstreams.yaml` | The MCP services behind Keystone-MCP. Mounted read-only, starts empty. |
| `Caddyfile` | TLS reverse proxy config (step 7). |

## 2. Create the Google OAuth client

Keystone-MCP asks Google who the person is, then checks that email in the
users directory. You need a client id, a client secret, and a redirect URI
that matches your domain:

```text
https://mcp.example.com/login/google/callback
```

Scopes are `openid email`; Keystone-MCP asks for nothing else. Full steps,
including the consent screen and restricting sign-in to one Workspace
domain: [google-oauth.md](../google-oauth.md).

## 3. Fill in `.env`

Open `.env`. Section 1 is the local profile; uncomment section 2 and edit it
for this deployment. Required:

| Variable | Value |
|---|---|
| `KEYSTONE_MCP_DEPLOYMENT_PROFILE` | `production` |
| `KEYSTONE_MCP_BASE_URL` | `https://mcp.example.com` |
| `KEYSTONE_MCP_HOST` | `0.0.0.0` |
| `KEYSTONE_MCP_REDIS_URL` | `redis://:<password>@redis:6379/0` |
| `KEYSTONE_MCP_THROTTLE_BACKEND` | `redis` (share tool-call and sign-in IP limits across replicas) |
| `KEYSTONE_MCP_USERS_DB_URL` | `postgresql+psycopg://keystone:<password>@postgres:5432/keystone` |
| `KEYSTONE_MCP_RBAC_MODE` | `enforce` (already the section-1 default; leave it) |
| `KEYSTONE_MCP_RBAC_POLICY_PATH` | `/etc/keystone-mcp/policy/rbac-policy.yaml` |
| `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` | output of `openssl rand -hex 32` |
| `KEYSTONE_MCP_SUPERADMIN_EMAIL` | the first administrator's email |
| `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH` | `/etc/keystone-mcp/login-providers.yaml` |
| `KEYSTONE_MCP_LOGIN_GOOGLE_SECRET` | Google client secret from step 2 (name must match `client_secret_env` in the providers file) |
| `KEYSTONE_MCP_UPSTREAMS_PATH` | `/etc/keystone-mcp/upstreams.yaml` |

Instead of putting Redis URL or audit salt in `.env`, you can mount Docker
secrets and set `KEYSTONE_MCP_REDIS_URL_FILE` / `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT_FILE`
to the mounted paths (see [environment.md#secrets-from-files](../environment.md#secrets-from-files)).

Edit `login-providers.yaml` with your Google `client_id` (and optional
`allowed_domain`). Removed in 0.5.0: delete any `KEYSTONE_MCP_AUTH_SERVICE_*`
lines from `.env` — startup refuses them.

The `keystone` service uses `init: true` so orphaned stdio upstream
processes are reaped, and `stop_grace_period: 35s` so in-flight requests can
finish after SIGTERM (see `KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` in
[environment.md](../environment.md)).

Add two more lines — Compose reads this same `.env` file to fill in
`docker-compose.yml`, separately from the variables above that Keystone-MCP
itself reads:

```bash
KEYSTONE_PG_PASSWORD=<password>
KEYSTONE_REDIS_PASSWORD=<password>
```

Pick each password with `openssl rand -hex 24` — characters like `@ : / ? #`
break the URL above if they land in a password. Use the **same** password in
`KEYSTONE_PG_PASSWORD` and in `KEYSTONE_MCP_USERS_DB_URL`, and the same in
`KEYSTONE_REDIS_PASSWORD` and `KEYSTONE_MCP_REDIS_URL`.

Then lock the file down: `chmod 600 .env`.

The production profile refuses to start with a weak configuration, not just
a warning in a log you might not read:

- DEV tokens: *"`KEYSTONE_MCP_DEV_TOKENS` is local-only: anyone holding one of
  these tokens signs in as any person in the users directory. Clear
  `KEYSTONE_MCP_DEV_TOKENS`, or set `KEYSTONE_MCP_DEPLOYMENT_PROFILE=local`."*
- SQLite users directory: *"`KEYSTONE_MCP_DEPLOYMENT_PROFILE=production` needs
  a Postgres users directory: set
  `KEYSTONE_MCP_USERS_DB_URL=postgresql+psycopg://user:password@host:5432/db`.
  SQLite is local-only (one file per replica, roles drift)."*
- Plain `http` on a public host: *"`KEYSTONE_MCP_BASE_URL` is a public http
  address (...); terminate TLS and use https."*

See [environment.md](../environment.md#deployment-profile) for every rule.

## 4. Write the policy file

`policy/rbac-policy.yaml` ships with one role, `administrator`, allowed `*`,
plus a commented-out second role to copy and adapt. A role can only be granted
to a person if its name is in this file. Format:
[rbac-policy-format.md](../rbac-policy-format.md).

Before `docker compose up`, ensure the container user (uid `10001` in the
official image) can write the policy directory — for example
`chown -R 10001:10001 policy` or `chmod 664 policy/rbac-policy.yaml` with a
group the container user shares. The directory must be writable, not only the
file, because atomic updates use `rename` in that directory.

## 5. List your services

`upstreams.yaml` starts with an empty `entries: []`. For each MCP service you
run beside Keystone-MCP, add an entry with its `name`, `url` (the Docker
service name, e.g. `http://your-service:8081/mcp`), and `namespace`. Run each
service on the same Compose network, with no published port.

Internal-network services usually speak plain `http`. Set
`KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true` in `.env` for that — the
traffic never leaves this Docker network, and production logs one warning at
startup: *"`KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true`: upstream calls
are not encrypted; keep upstreams on a private network."* An unreachable
service does not block startup — Keystone-MCP logs a warning and retries it
on the next refresh tick; set `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true` to
refuse startup instead. Contract your services must meet:
[connecting-services.md](../connecting-services.md).

## Adding catalog services

Instead of editing `upstreams.yaml` by hand, this directory can be adopted
by an installer such as [keystonectl](https://github.com/keystone-codes/keystonectl)
with `keystonectl init --adopt .`: it recognizes the layout from this guide
and adds its own Compose override file to install catalog services next to
Keystone-MCP, without editing `docker-compose.yml`, `.env`, the policy, or
`upstreams.yaml`.

## 6. Start the stack

```bash
docker compose up -d --wait
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Set `init: true` on the Keystone-MCP service (or run `docker run --init`) so
orphaned stdio-upstream child processes are reaped. After SIGTERM the server
waits up to `KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` (default 25) for in-flight
requests; allow at least 35 s when stopping (`stop_grace_period: 35s` in
Compose, `docker stop -t 35`). The image healthcheck loads `.env` and honours
`KEYSTONE_MCP_HOST` when choosing the probe URL.

`--wait` blocks until every container's healthcheck passes, including
Keystone-MCP's own `/readyz` poll (Redis, the RBAC policy, and the Postgres
users directory — see [observability-logging.md](../observability-logging.md#readiness)).
`/healthz` returns `{"status":"ok"}` once the process is up; `/readyz`
returns `{"status":"ok"}` (`200`) once all three dependencies answer, or
`{"status":"degraded"}` (`503`) while one of them is not ready yet.

**Stop here if you are tempted to call the deployment done.** `/healthz` and
`/readyz` check the process, Redis, the RBAC policy, and the users directory
— they never contact the login provider. Step 8 (sign in as the first
administrator) is mandatory, not optional verification: it is the only check
in this guide that proves Google (or your OIDC provider) actually accepts a
sign-in and that Keystone-MCP accepts it back. See
[production-checklist.md](../production-checklist.md#smoke-after-deploy) for
the full smoke-test split between infrastructure and sign-in checks.

## 7. Put TLS in front

Keystone-MCP only listens on `127.0.0.1:8080`; a reverse proxy on the host
terminates TLS and forwards to it.

**Caddy** (the included `Caddyfile`, edit the hostname first):

```bash
caddy run --config Caddyfile
```

Or install Caddy as a package and point it at the same file; it gets a
certificate for you automatically.

**nginx**, for reference (inside your own `server { listen 443 ssl; ... }`
block):

```nginx
proxy_pass http://127.0.0.1:8080;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_buffering off;
```

`proxy_buffering off` matters: Streamable HTTP sends events as a stream, and
a buffering proxy holds them back until the response closes.

Either way, set `FORWARDED_ALLOW_IPS` (a plain uvicorn/environment variable,
no `KEYSTONE_MCP_` prefix) so the login rate limiter sees the real client
address instead of the proxy's. A proxy on the host talking to Keystone-MCP
inside this Compose stack sees the container through the Docker bridge, not
`127.0.0.1` — find the bridge gateway with
`docker network inspect keystone-production_keystone -f '{{(index .IPAM.Config 0).Gateway}}'`
and set `FORWARDED_ALLOW_IPS` to that address before starting Keystone-MCP.
Full explanation: [environment.md](../environment.md#behind-a-reverse-proxy).

## 8. Sign in as the first administrator

Connect an MCP client to `https://mcp.example.com` (see
[clients.md](../clients.md) for client setup) and sign in with the Google
account matching `KEYSTONE_MCP_SUPERADMIN_EMAIL`. Keystone-MCP creates that
account on first start and grants it `administrator`.

## 9. Add people

Once signed in, ask the agent to add someone — it calls the built-in
`users_*` tools. The agent's checklist is the skill
[`keystone-user-admin`](../../skills/keystone-user-admin/SKILL.md); copy that
folder into your client's skills directory. Full reference:
[users.md](../users.md).

If the administrator account is ever lost, recover it from the host, not
through the agent:

```bash
docker compose exec keystone keystone-mcp users grant-admin --email recovery@example.com
```

## Upgrades and backups

**Upgrade:** change the image tag in `docker-compose.yml`, then:

```bash
docker compose pull
docker compose up -d --wait
```

Users-directory migrations run automatically at startup; Postgres's
transactional advisory lock means several replicas starting at once do not
race each other.

**Backup** the users directory:

```bash
docker compose exec postgres pg_dump -U keystone keystone > backup.sql
```

Redis holds sessions and pending logins only, not people or roles — losing
it signs everyone out, nothing else.

## Running more than one replica

Scale the `keystone` service and put a load balancer in front of it. OAuth
clients, tokens, pending logins and the users-directory revision marker
live in Redis and are shared; the rate limiters, the users-directory
allow/deny cache and the live tool catalog are per process, so a person's
effective call budget multiplies by the replica count. If the load
balancer forwards a `Host` other than `mcp.example.com`, add that name to
`KEYSTONE_MCP_ALLOWED_HOSTS`, or every request gets `421`. Postgres is
required for this (SQLite does not work with more than one replica).
Details: [environment.md](../environment.md#rate-limits-reverse-proxies-and-replicas).

## Before you go live

Walk through [production-checklist.md](../production-checklist.md).
