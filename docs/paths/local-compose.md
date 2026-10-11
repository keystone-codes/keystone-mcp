# Run Keystone-MCP on your machine

In about 15 minutes: three containers (Keystone-MCP, Redis, a sample
upstream service), one sign-in with a DEV token, that service's tools in
your catalog, a second person with a smaller role, and their catalog
shrinking to match.

> **Local only.** The DEV token is a shared password: anyone holding it can
> sign in as any email already in the users directory. This demo binds to
> `127.0.0.1` only — never expose it on a public interface. For a real host,
> use [the production path](production-docker.md) instead.

## What you need

- Docker Desktop or Docker Engine with Compose v2 (`docker compose version`
  must print `v2.x` or newer), and `git`.
- About 2 GB of free memory for Docker, and port 8080 free (see
  Troubleshooting if it is not).
- One MCP client: Claude Code, Cursor, or Claude Desktop (also needs
  Node.js 18+ — see its section below).

## 1. Start the demo

```bash
git clone https://github.com/keystone-codes/keystone-mcp.git
cd keystone-mcp
docker compose -f docker-compose.demo.yml up -d --build --wait
```

The first build takes 2–5 minutes; `--wait` returns once all three
containers report healthy.

To use your own token and administrator email instead of the defaults
(`demo-token` and `admin@example.com`, used for the rest of this page):

```bash
KEYSTONE_DEMO_TOKEN=<your-token> KEYSTONE_DEMO_ADMIN_EMAIL=<your-email> \
  docker compose -f docker-compose.demo.yml up -d --build --wait
```

## 2. Check that it is up

```bash
docker compose -f docker-compose.demo.yml ps
```

You should see three services, each `(healthy)`:

```
NAME                          STATUS
keystone-demo-hello-upstream-1   Up ... (healthy)
keystone-demo-keystone-1         Up ... (healthy)
keystone-demo-redis-1            Up ... (healthy)
```

```bash
curl -fsS http://localhost:8080/healthz
```

You should see:

```json
{"status":"ok"}
```

## Check the whole install with one command

This script runs the full scenario below in one shot — sign-in, every
`hello_*` tool, adding a member, and confirming the member's catalog has no
`users_*`:

```bash
uv run python scripts/smoke_demo.py --base-url http://localhost:8080 \
  --dev-token demo-token --admin-email admin@example.com
```

You should see twelve `[PASS]` lines, ending in `12/12 steps passed.` A
`[FAIL] <step>: expected <X>, got <Y>` line names exactly which part broke.

## 3. Connect your MCP client

The server address is `http://localhost:8080/`. Clients register themselves
automatically (dynamic client registration) — nothing to create by hand.
The short blocks below cover the local address; [clients.md](../clients.md)
has the full steps for each client, sign-out, and a public address.

### Claude Code

```bash
claude mcp add --transport http keystone http://localhost:8080/
```

In a Claude Code session, run `/mcp`, select `keystone`, then
**Authenticate**. Your browser opens to the sign-in page.

### Cursor

Add to `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{ "mcpServers": { "keystone": { "url": "http://localhost:8080/" } } }
```

Open Settings → MCP, find `keystone`, click **Connect** (or **Login**) —
your browser opens to the sign-in page.

### Claude Desktop

Claude Desktop's built-in connectors run from Anthropic's cloud and cannot
reach `http://localhost:8080`. The workaround is a local bridge,
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) (needs Node.js
18+). Add to `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "keystone": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:8080/"]
    }
  }
}
```

Restart Claude Desktop. Your browser opens to the sign-in page. If this
bridge does not complete sign-in for you, use a public HTTPS address and
the ordinary connector flow in Settings → Connectors instead (the
[production path](production-docker.md) covers getting a public address).

## 4. Sign in as the administrator

On the sign-in page, enter email `admin@example.com` and DEV token
`demo-token`. Keystone-MCP created this account on first start from
`KEYSTONE_MCP_SUPERADMIN_EMAIL` in `docker-compose.demo.yml` and granted it
`administrator`. An email that is *not* in the users directory is refused
even with a correct token — the page shows "User is not registered or is
blocked".

## 5. Look at the catalog

Ask your agent: "List the tools from keystone" (or check the client's own
tool list).

You should see a `hello` section (`hello_greet`, `hello_search`) plus eight
`users_*` tools (`users_add`, `users_block`, `users_grant_role`, `users_list`,
`users_revoke_role`, `users_set_roles`, `users_unblock`, `users_update`).

Ask: "Call hello_greet with name Ada." You should see:

```
Hello, Ada! You are admin@example.com.
```

Keystone-MCP sent your verified email to the `hello` service in an
`X-Author-Email` header; the service itself never checked who you are.

## 6. Add a second person with a smaller role

Ask your agent: "Add bob@example.com, full name Bob, with role member." It
calls the built-in `users_add` tool.

`member` comes from the demo's policy file,
[`examples/demo/rbac-policy.yaml`](../../examples/demo/rbac-policy.yaml):

```yaml
# Demo policy. Two roles: administrator sees everything,
# member sees only the hello_* section.
version: "demo-1"
default_deny: true
roles:
  administrator:
    description: "Everything, including user administration."
    allow: ["*"]
  member:
    description: "Only the hello service."
    allow: ["hello_*"]
```

`administrator` can call anything; `member` can only call tools starting
with `hello_`. An unknown role is refused: `validation_error: unknown role: <name>`.

## 7. Sign in as that person

Sign out of the `admin@example.com` session and sign in again as
`bob@example.com`, same DEV token (`demo-token`):

- **Claude Code:** `/mcp` → `keystone` → **Clear authentication**, then
  **Authenticate**.
- **Cursor:** Settings → MCP → `keystone` → **Logout**, then **Login**.
- **Claude Desktop with `mcp-remote`:** quit Claude Desktop, delete the
  `~/.mcp-auth` folder, then open Claude Desktop again.

You should see only `hello_greet` and `hello_search` in the catalog —
`users_*` is gone. Ask the agent to call `users_list`: it is refused,
because the tool is not in `bob@example.com`'s catalog at all.

## 8. What just happened

Three independent settings decided what you could see and do: **who
exists** (the users directory — just `admin@example.com` and
`bob@example.com`), **how they prove it** (the DEV token here; Google in
production), and **what they may call** (the policy file — `*` for
`administrator`, `hello_*` for `member`). Changing one never touches the
others. Full explanation: [../security-model.md](../security-model.md).

## Stop, reset, restart

```bash
docker compose -f docker-compose.demo.yml down       # stop; keep the data
docker compose -f docker-compose.demo.yml down -v    # stop and wipe the data
```

Editing `examples/demo/rbac-policy.yaml` needs no restart: Keystone-MCP
re-reads it every five minutes on its own, or immediately with:

```bash
docker compose -f docker-compose.demo.yml kill -s HUP keystone
```

## Use Postgres instead of SQLite

The demo defaults to a SQLite users directory. To prove it against Postgres
instead (the deployment profile stays `local`; DEV sign-in keeps working):

```bash
KEYSTONE_PG_PASSWORD=<password> \
  docker compose -f docker-compose.demo.yml -f docker-compose.postgres.yml \
  up -d --build --wait
```

Postgres in production is covered by the [production path](production-docker.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Bind for 127.0.0.1:8080 failed: port is already allocated` | Something else is already using port 8080 | Stop that process, or change the left side of `ports:` for the `keystone` service in `docker-compose.demo.yml` to a free port (e.g. `127.0.0.1:18080:8080`) **and** change `KEYSTONE_MCP_BASE_URL` in the same file to match (`http://localhost:18080`) — both have to agree |
| `keystone` container is `unhealthy` | Startup validation failed, or a dependency is not ready | `docker compose -f docker-compose.demo.yml logs keystone` — look for the refusal message near the end; it names the setting to fix |
| Sign-in page shows "User is not registered or is blocked" | The email you typed is not in the users directory (or is blocked), or you mistyped it | Sign in with `admin@example.com` (or whichever email `users_add` created), not an arbitrary address |
| Client never opens a browser, or you get a `401` | A stale or missing authorization | Repeat the sign-out/sign-in steps in step 7 above |
| No `hello` section in the catalog | The `hello-upstream` service is not reachable yet | `docker compose -f docker-compose.demo.yml logs hello-upstream` and confirm it is healthy; Keystone-MCP retries discovery every five minutes, or sooner after `kill -s HUP` |
| First `docker compose ... up --build` is slow | Normal, especially on Apple Silicon the first time | Wait for the 2–5 minute build; later runs reuse the cached image |

## Next steps

- Connect your own service: [../connecting-services.md](../connecting-services.md)
- Write your own policy: [../rbac-policy-format.md](../rbac-policy-format.md)
- Manage people: [../users.md](../users.md) and the
  [`keystone-user-admin`](../../skills/keystone-user-admin/SKILL.md) skill
- Move to a real host: [production-docker.md](production-docker.md)
- Every document: [../../README.md](../../README.md)
