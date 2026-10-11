# Install Keystone-MCP on a host with systemd

For Docker, use [paths/production-docker.md](paths/production-docker.md) —
that is the main production path. This page is for a host that runs
Keystone-MCP directly, without a container.

## What you need

- Python 3.11+ and [uv](https://docs.astral.sh/uv/).
- Redis (required for OAuth session state).
- PostgreSQL (the built-in users directory needs it in production; see
  [environment.md](environment.md#deployment-profile)).
- A TLS-terminated reverse proxy in front of Keystone-MCP.

## 1. Install

```bash
git clone https://github.com/keystone-codes/keystone-mcp.git
cd keystone-mcp
uv sync --locked
sudo useradd --system --home-dir /opt/keystone-mcp --shell /usr/sbin/nologin keystone-mcp
sudo mkdir -p /opt/keystone-mcp
sudo rsync -a --exclude .git ./ /opt/keystone-mcp/
sudo chown -R keystone-mcp:keystone-mcp /opt/keystone-mcp
```

`uv sync --locked` installs only the runtime dependencies, not the
development tooling a contributor's checkout uses.

If the repository still has `setup.sh` at its root: `./setup.sh` writes a
`.env` for this layout interactively, with a `local` or `production`
profile; pass `--non-interactive` to drive it from `KEYSTONE_SETUP_*`
variables instead (see `./setup.sh --help`).

## 2. Configure

```bash
cp .env.example /opt/keystone-mcp/.env
sudo chmod 600 /opt/keystone-mcp/.env
$EDITOR /opt/keystone-mcp/.env
```

Fill in section 2 of `.env` the same way as
[step 3 of the Docker path](paths/production-docker.md#3-fill-in-env), with
two differences for a bare host instead of containers:

| Variable | Docker path | This host |
|---|---|---|
| `KEYSTONE_MCP_HOST` | `0.0.0.0` | `127.0.0.1` (the reverse proxy runs on the same host) |
| `KEYSTONE_MCP_REDIS_URL` | `redis://:<password>@redis:6379/0` | `redis://:<password>@127.0.0.1:6379/0`, or wherever Redis actually runs |
| `KEYSTONE_MCP_USERS_DB_URL` | `postgresql+psycopg://keystone:<password>@postgres:5432/keystone` | same, with your Postgres host in place of `postgres` |

Register the Google OAuth redirect URI,
`{KEYSTONE_MCP_BASE_URL}/login/google/callback` — see
[google-oauth.md](google-oauth.md). Pre-flight checklist:
[production-checklist.md](production-checklist.md).

## 3. Run with systemd

```ini
[Unit]
Description=Keystone-MCP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=keystone-mcp
WorkingDirectory=/opt/keystone-mcp
EnvironmentFile=/opt/keystone-mcp/.env
ExecStart=/usr/local/bin/uv run python -m keystone_mcp.server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install the unit, `systemctl daemon-reload`, then
`systemctl enable --now your-keystone-mcp.service`. Configure your reverse
proxy to forward HTTPS to `http://127.0.0.1:<port>/` — see
[production-docker.md, step 7](paths/production-docker.md#7-put-tls-in-front)
for the same Caddy/nginx configuration; `FORWARDED_ALLOW_IPS` is simpler on a
bare host, since the proxy's peer address is already `127.0.0.1` with no
Docker bridge in between.

## 4. Routine updates

From the repository root on the server:

```bash
./scripts/deploy.sh
```

The script runs `git pull`, reinstalls dependencies with `uv sync --locked`,
restarts the configured systemd unit, and checks `/healthz`. It installs
runtime dependencies only. Override behaviour with
`SKIP_GIT`, `SKIP_RESTART`, `SKIP_SMOKE`, `DEPLOY_SERVICE`, and
`DEPLOY_HEALTH_URL` (see the script's own header comment).

## 5. Verify

```bash
curl -fsS "https://mcp.example.com/healthz"
curl -fsS "https://mcp.example.com/readyz"
```

Connect your MCP client to the public base URL and sign in — see
[production-docker.md, step 9](paths/production-docker.md#9-add-people) for
adding people once the first administrator is in.

## Troubleshooting

```bash
journalctl -u your-keystone-mcp.service -f
ss -ltnp | grep <port>
```

A refusal to start names the variable and the rule it violates — see the
deployment-profile table in [environment.md](environment.md#deployment-profile).
