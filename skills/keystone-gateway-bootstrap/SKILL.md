---
name: keystone-gateway-bootstrap
description: Install the Keystone-MCP gateway from scratch for production and prove it with a live sign-in — Docker on a VM, sign-in with Google or any OIDC provider, TLS, the first administrator. Use when asked to install Keystone-MCP from scratch, set up a production gateway or a stand, set up sign-in with Google or OIDC, or change the login provider; and before installing any service with keystonectl when no gateway is running yet.
---

# Install the Keystone-MCP gateway

This skill walks one installation of the gateway itself, in order, and does not
let you call it ready early. Green `/healthz`, `/readyz` and `config check`
do not prove that a person can sign in: a gateway can pass all of them and
still answer every sign-in with 503 "The identity provider is unavailable".
The installation is done only when the first administrator has signed in
through the provider in a real client (see [Done means](#done-means)).

The full walkthrough with every file and value is
[production-docker.md](../../docs/paths/production-docker.md). This skill gives
the order, the questions, the rules and the checks; follow the walkthrough for
the details of each step and do not improvise around it.

## Where you run

On the gateway server itself, or through the SSH wrapper the operator gave
you. This skill keeps no keys, passwords or SSH credentials, and you do not
ask for them.

## Decide with the operator, one question at a time

Ask these in order, one per message. Offer only the options listed here; do
not invent others. Do not start a step before its answers are in.

1. **Where to install.**
   - Docker on a VM, per [production-docker.md](../../docs/paths/production-docker.md) — supported; continue.
   - keystone-deploy — stop. Its setup does not configure a login provider yet; stop and tell the operator.
   - Kubernetes or Helm — stop. This version of the skill does not cover them; say so.
2. **How people sign in.**
   - Google.
   - OIDC (Okta, Entra, Keycloak, …) — ask for the `issuer` and the `client_id`.
   - API keys only. Name the cost before they choose: the `users_*` and
     `policy_*` tools will not work through the agent, because the production
     policy marks them `requires_human_identity` and an API key is not a person
     who signed in through a provider. Nobody can add people or change roles
     through the agent on such a gateway.
3. **The gateway domain**, for example `mcp.example.com`. It becomes
   `KEYSTONE_MCP_BASE_URL=https://mcp.example.com`. Only `https`; refuse a
   plain `http` address.
4. **The first administrator's email.** It becomes
   `KEYSTONE_MCP_SUPERADMIN_EMAIL`. The gateway creates that account on every
   start and grants it `administrator`.
5. **A Workspace (or company) email domain**, if sign-in must be limited to
   one. Google: `allowed_domain`; OIDC: `allowed_domains`. Optional.
6. **Will you run boxes (stdio servers behind the gateway)?** If yes, ask the
   operator once to add a wildcard DNS record `*.boxes.<domain>` pointing at
   this server, so the credential forms of every box later get an address
   without a new DNS record each time.

## What only the operator does

- The server and access to it.
- The DNS A record for the gateway domain (and the `*.boxes.<domain>` wildcard
  if they chose boxes).
- The OAuth client at the provider — the Google Cloud console or the OIDC
  provider's admin page — with the redirect URI
  `{BASE_URL}/login/<provider>/callback` (for Google
  `https://mcp.example.com/login/google/callback`) and the scopes
  `openid email`. Google details: [google-oauth.md](../../docs/google-oauth.md).
- The client secret. It never passes through you.
- The browser sign-in. You cannot sign in for them.

## Secrets

1. **Never ask for a secret in chat and never read `.env`.** Do not `cat`,
   `grep`, `source`, `head` or open `.env` or any secret file, and do not run
   a command that prints one.
2. **The client secret** goes into `.env` by the operator's own command, from
   the operator's own mode 600 file. Give them these two commands for their
   terminal; do not run them. `KEYSTONE_MCP_LOGIN_GOOGLE_SECRET` is the
   variable name the production example uses for Google
   (`examples/production/login-providers.yaml`); it must match whatever
   `client_secret_env` actually names in the `login-providers.yaml` this
   deployment ships (the shipped example already names one; keep it). For an
   OIDC provider, use that provider's own `client_secret_env` name instead.

   ```
   <!-- operator-command -->
   install -m 600 /dev/null /root/keystone-secrets/login-client-secret && nano /root/keystone-secrets/login-client-secret
   <!-- operator-command -->
   printf '%s=%s\n' 'KEYSTONE_MCP_LOGIN_GOOGLE_SECRET' "$(cat /root/keystone-secrets/login-client-secret)" >> /srv/keystone/.env
   ```

3. **Redis and Postgres passwords and the audit salt** you generate with one
   command that writes them straight into `.env`, prints nothing, and puts the
   **same** Postgres password into both `KEYSTONE_PG_PASSWORD` and
   `KEYSTONE_MCP_USERS_DB_URL` (and the same Redis password into both
   `KEYSTONE_REDIS_PASSWORD` and `KEYSTONE_MCP_REDIS_URL`). Run it once, after
   `.env` exists with mode 600:

   ```bash
   cd /srv/keystone && (
     umask 077
     pg="$(openssl rand -hex 24)"
     rd="$(openssl rand -hex 24)"
     printf 'KEYSTONE_PG_PASSWORD=%s\n' "$pg"
     printf 'KEYSTONE_MCP_USERS_DB_URL=postgresql+psycopg://keystone:%s@postgres:5432/keystone\n' "$pg"
     printf 'KEYSTONE_REDIS_PASSWORD=%s\n' "$rd"
     printf 'KEYSTONE_MCP_REDIS_URL=redis://:%s@redis:6379/0\n' "$rd"
     printf 'KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT=%s\n' "$(openssl rand -hex 32)"
   ) >> .env
   ```

   Hex passwords never contain `@ : / ? #`, so they do not break the URLs.
4. **Secrets live in `.env`, not in `_FILE` mounts, on this path.** A mode 600
   file owned by a host user cannot be read by the container user (uid
   `10001`), so a `…_FILE` variable pointing at it fails at startup.
5. **If a person pastes a secret into chat,** do not repeat it, do not use it,
   and ask them to rotate it at its source and enter the new one with the
   operator command above.

## Steps

Each step says who does it. Details are in the named section of
[production-docker.md](../../docs/paths/production-docker.md); do not copy it
here or skip parts of it.

1. **Server and domain — operator.** A Linux server with Docker and Compose
   v2, port 443 open, the A record (and the boxes wildcard) pointing at it.
   Walkthrough: "What you need".
2. **Client at the provider — operator.** The OAuth client with the redirect
   URI and scopes from [What only the operator does](#what-only-the-operator-does).
   Ask them to tell you the exact redirect URI they entered; you compare it in
   the Checks section. Walkthrough: the Google OAuth
   client section.
3. **Deployment files — agent.** Walkthrough: "Get the files", "Fill in
   `.env`", "Write the policy file", "List your services".
   - Copy `examples/production` to the deployment directory (the walkthrough
     uses `/srv/keystone`).
   - Set the `keystone` image tag in the copied `docker-compose.yml` to the
     release you install. With Google it must be 0.6.0 or later: 0.5.0 refused
     every Google sign-in. A tag is not proof of the version inside; the
     provider log line is (see Checks).
   - Create `.env` with mode 600 without overwriting an existing one:
     `test ! -e .env && install -m 600 /dev/null .env`. Append the non-secret
     settings from the walkthrough's `.env` table (profile `production`,
     `KEYSTONE_MCP_BASE_URL`, `KEYSTONE_MCP_HOST`, `KEYSTONE_MCP_THROTTLE_BACKEND`,
     `KEYSTONE_MCP_RBAC_MODE`, `KEYSTONE_MCP_RBAC_POLICY_PATH`,
     `KEYSTONE_MCP_SUPERADMIN_EMAIL`, `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`,
     `KEYSTONE_MCP_UPSTREAMS_PATH`) with `cat >> .env <<'EOF'`, then run the
     secrets command from [Secrets](#secrets), then give the operator the
     client-secret commands and wait until they say it is done.
   - Edit `login-providers.yaml`: the `client_id` (and `issuer` for OIDC, and
     the allowed domain if they gave one). No secret goes into this file — only
     the variable name in `client_secret_env`. For "API keys only", keep only a
     `type: api_key` entry.
   - Make the `policy/` directory writable by uid `10001`, as the walkthrough
     says.
   - Before the first start, run `config check` in the container (see
     [Commands](#commands-this-skill-may-run)) and fix every `ERROR`.
4. **Start — agent.** `docker compose up -d --wait`, then `curl` `/healthz` and
   `/readyz`. Walkthrough: "Start the stack".
5. **TLS — agent.** Caddy (the included `Caddyfile`) or nginx with
   `proxy_buffering off`. Find the Docker bridge gateway with
   `docker network inspect`, append `FORWARDED_ALLOW_IPS=<that address>` to
   `.env`, and run `docker compose up -d --wait` again so the container gets
   it. Walkthrough: "Put TLS in front".
6. **First sign-in — operator, with you.** The operator signs in in their own
   MCP client through the provider, with the administrator email. Connect your
   own MCP client to `https://<domain>/` per [clients.md](../../docs/clients.md)
   and have the operator complete the browser sign-in as the administrator.
   If the `users_*` and `policy_*` tools appear only in a new session of your
   client, say so plainly and ask the operator to start one. Walkthrough:
   "Sign in as the first administrator".
7. **People and roles — hand off.** Add people with the
   [`keystone-user-admin`](../keystone-user-admin/SKILL.md) skill; change roles
   with the [`keystone-policy-admin`](../keystone-policy-admin/SKILL.md) skill.

Before calling it live, walk the operator through
[production-checklist.md](../../docs/production-checklist.md).

## Commands this skill may run

Run nothing else on the server, apart from the file setup in step 3
(`cp`, `install -m 600`, appending to `.env`, editing the copied YAML) and the
secrets command in [Secrets](#secrets). Nothing that reads or prints `.env` or
any secret.

| Command | Why |
|---|---|
| `docker compose run --rm --no-deps keystone keystone-mcp config check` | Before the first start: every startup refusal (`ERROR`) and warning, from the same `.env`. Secrets are redacted. |
| `docker compose exec keystone keystone-mcp config check` | The same once the stack runs. |
| `docker compose up -d --wait` | Start or recreate the stack and wait for every healthcheck. |
| `docker compose ps` | Container state and health. |
| `docker compose logs keystone` | Startup log of the gateway; filter it with `grep 'login provider'` for the checks below. |
| `docker network inspect keystone-production_keystone -f '{{(index .IPAM.Config 0).Gateway}}'` | The bridge address for `FORWARDED_ALLOW_IPS`. |
| `curl -fsS http://127.0.0.1:8080/healthz` | The process is up. |
| `curl -fsS http://127.0.0.1:8080/readyz` | Redis, policy and users directory answer. |

## Checks — what each one proves

Climb the ladder in order. **The first four rungs do not check sign-in.**
In particular, `readyz` does not check sign-in: it never calls the identity
provider.

| # | Check | Proves | Does not prove |
|---|---|---|---|
| 1 | `config check` with no `ERROR` | The settings pass every startup rule. | Anything about Redis, Postgres or the provider — it connects to none of them, OIDC discovery included. |
| 2 | Start without a refusal (`docker compose ps` healthy) | The process accepted the settings and started. | Sign-in: a provider that fails to warm up only logs a WARNING and the gateway starts anyway. |
| 3 | `/healthz` → 200 | The process listens. | Dependencies, sign-in. |
| 4 | `/readyz` → 200 | Redis, the policy, the users directory and background startup are ready. | Sign-in: `readyz` does not check the login provider. |
| 5 | Live sign-in | A person with the administrator email signed in through the provider. | — |
| 6 | One tool call | The signed-in administrator called one tool, for example `users_list`, and got an answer. | — |

Before rung 5 you may check three things in `docker compose logs keystone`
and report them. They make a failure at rung 5 less likely; they do **not**
make the gateway ready, and you do not say it is:

1. **The provider line.** At startup the gateway logs, for each redirect
   provider, `login provider <name>: type <type> from keystone-mcp-gateway <version>, callback <BASE_URL>/login/<name>/callback`.
   Report the version and the callback. With Google the version must be
   0.6.0 or later.
2. **No warm-up WARNING.** No `login provider <name> is not ready: …` and no
   `login provider <name> warm_up …` line. Either one means the gateway could
   not reach the provider's discovery or keys at startup.
3. **The callback matches.** The callback in the provider line is exactly the
   redirect URI the operator entered at the provider in step 2.

## Done means

A person with the `KEYSTONE_MCP_SUPERADMIN_EMAIL` email signed in through the
provider in a real MCP client and saw the `users_*` and `policy_*` tools
(rungs 5 and 6). Until then, report what passed and say plainly that the
gateway is not confirmed ready.

The operator may waive this check only by saying so explicitly. Then write the
waiver in your final summary: "Live sign-in not checked: waived by the
operator."

## Next

- Services behind the gateway — the `keystonectl` skill
  ([keystonectl repository](https://github.com/keystone-codes/keystonectl),
  `skills/keystonectl/`).
- People — [`keystone-user-admin`](../keystone-user-admin/SKILL.md).
- Roles — [`keystone-policy-admin`](../keystone-policy-admin/SKILL.md).

## Errors

| Symptom | Where to look |
|---|---|
| 503 "The identity provider is unavailable" when the sign-in button is pressed | `docker compose logs keystone`: the provider line, its version (Google needs 0.6.0 or later), and a warm-up WARNING for that provider. |
| Google shows `redirect_uri_mismatch` | The redirect URI in the Google console does not match the callback in the provider line. See [google-oauth.md](../../docs/google-oauth.md). |
| 403 "User is not registered or is blocked" | The email is not in the users directory (or is blocked). For the first administrator, check `KEYSTONE_MCP_SUPERADMIN_EMAIL` with the operator; for others, use `keystone-user-admin`. |
| `421 Misdirected Request` | The `Host` the proxy forwards is not the host in `KEYSTONE_MCP_BASE_URL`. Fix the proxy (`proxy_set_header Host $host`) or add the name to `KEYSTONE_MCP_ALLOWED_HOSTS`. |
| `ERROR` lines in `config check` | Each line names the setting and the rule; fix it in `.env` and run `config check` again. See [environment.md](../../docs/environment.md). |

More sign-in symptoms: [clients.md](../../docs/clients.md), "If sign-in does
not work".
