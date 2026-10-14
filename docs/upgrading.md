# Upgrading Keystone-MCP

Use this page when you move between minor releases. Each section lists checks
for operators before traffic hits a new version, what happens to live OAuth
sessions, how to roll back, and which metrics to watch afterward.

## 0.5.x → 0.6.0

### Before you upgrade

1. **Configuration** — Install or unpack the 0.6.0 binary or image, keep your
   production `.env` and secrets unchanged, and run:

   ```bash
   keystone-mcp config check --env-file /path/to/.env
   keystone-mcp config check --env-file /path/to/.env --strict
   keystone-mcp config check --env-file /path/to/.env --admins
   ```

   Fix every `ERROR` line (exit code `1`). Compare warnings with
   [environment.md](environment.md#startup-warnings); `--strict` treats warnings
   as failures. The command reports which settings now refuse startup and which
   only warn.

2. **Management roles and administrators** — On the new version, before you
   switch traffic:

   ```bash
   keystone-mcp users admins --env-file /path/to/.env
   ```

   It lists full administrators, every management role from the active policy,
   and who holds each role. Exit code `1` means there is no active full
   administrator; use `keystone-mcp users grant-admin` as described in
   [users.md](users.md) before upgrading.

   Service accounts must not hold roles that reach built-in administration
   tools; automation that used a service-account token for `users_*`,
   `service_accounts_*`, `api_keys_*`, or mutating `policy_*` will get
   `forbidden` after upgrade. Run those changes from a person's session or
   from the `keystone-mcp` CLI on the host.

3. **Users directory secrets** — If `KEYSTONE_MCP_USERS_BACKEND_CONFIG` (or any
   plugin directory config file) embeds secrets under keys such as
   `client_secret`, `api_key`, or `private_key`, move each value to an
   environment variable and reference it with `<key>_env`. Inline secrets refuse
   startup in 0.6.0.

4. **Sign-in providers** — Move Google (and other OIDC) client settings into a
   providers file (`KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`) if you still rely on
   legacy env-only variables. Deprecated variables keep working with a warning;
   `config check` lists them. If `email_claim` is not `email` and
   `require_email_verified` is on, set `email_verified_claim` in the provider
   entry (or turn verification off explicitly).

5. **Policy and Redis** — Ensure every replica that mounts the policy file sees
   the same content, or plan to copy the file and send `SIGHUP` when
   `keystone_mcp_rbac_policy_in_sync` drops to `0`. Give Keystone-MCP a
   dedicated Redis instance or an ACL user limited to its key prefixes.

### What changes for live sessions

- **Surviving the upgrade** — OAuth sessions opened on 0.4.x or 0.5.x keep
  working after you deploy 0.6.0. Refresh-token markers gain extra fields; older
  code ignored unknown JSON fields, and 0.6.0 extends the marker rather than
  invalidating existing sessions.

- **Refresh grace** — `KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS` defaults to
  `10`. A second `POST /token` with the same refresh token inside that window
  receives the same token pair (`grace_reissue` in audit and metrics). A reuse
  after the window revokes every token for that person at that OAuth client
  (`replay_revoked`). While 0.5.x and 0.6.0 replicas run side by side, a token
  rotated on a 0.5.x replica is not treated as a replay; full detection applies
  once every replica runs 0.6.0.

- **Session max age** — `KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS` defaults to
  `2592000` (30 days). A session cannot be renewed longer than that after
  sign-in; `0` means no limit. Sessions opened before you set or upgrade count
  from their first renewal after the limit applies.

- **Directory and API keys on refresh** — Each refresh re-checks the person in
  the users directory and the API key the session was opened with. While the
  directory is unreachable, `/token` returns `503` and the refresh token stays
  valid. Revoking someone's API key ends all of their sessions, including ones
  opened before 0.6.0.

- **Token storage in Redis** — Access and refresh tokens are stored under
  SHA-256 hashes. Legacy plain keys are migrated on first use (metric
  `keystone_mcp_oauth_token_keys_migrated_total`). There is no env switch to
  keep plain keys; plan upgrades and rollbacks with that in mind.

### Rolling back

- **Application version** — You can run the 0.5.x image or package again against
  the same Postgres data and policy files. Database migration `0004` adds
  nullable columns; 0.5.x ignores them. New policy fields and registry limits
  enforced only in 0.6.0 stop applying when you roll back.

- **Sessions and Redis** — Sessions opened on 0.6.0 remain usable on 0.5.x: 0.5.x
  ignores the new marker fields. If you roll back **after** 0.6.0 has written
  hashed token keys, 0.5.x cannot read those Redis entries — **everyone must sign
  in again**. There is no plain/hash mode toggle. Side-by-side 0.5.x and 0.6.0
  replicas may strip new marker fields when a 0.5.x replica renews a session;
  session max-age and refresh replay rules apply fully only when all replicas
  run 0.6.0.

- **Refresh replay window** — Rolling back to 0.5.x restores the previous
  longer grace behaviour for replay detection; no Redis data is deleted for that
  alone.

- **Operational checks** — After rollback, run `keystone-mcp config check` with
  the 0.5.x binary if you changed environment variables for 0.6.0-only features.

### After you upgrade

Watch these signals during the first 24 hours (`KEYSTONE_MCP_METRICS_ENABLED=true`;
see [observability-rbac.md](observability-rbac.md#example-promql-alert-rules)):

- **`keystone_mcp_admin_refusals_total`** — Unexpected refusals (especially
  `reason="service_account"`) mean automation or policy still expects the old
  administration model.
- **`keystone_mcp_oauth_token_exchange_total`** — Spikes in `grace_reissue`,
  `replay_revoked`, `code_replay`, `user_denied`, or `directory_unavailable`
  point to client behaviour or directory health.
- **`keystone_mcp_api_key_verifications_total`** and cache gauges — Garbage key
  probes or cache pressure after hardening.
- **`keystone_mcp_oauth_client_evictions_total`** — Heavy DCR churn at
  `KEYSTONE_MCP_OAUTH_MAX_CLIENTS`.
- **`keystone_mcp_upstream_input_rounds_exceeded_total`** and
  **`keystone_mcp_upstream_items_rejected_total`** — Upstream misconfiguration
  or catalog limits.
- **`keystone_mcp_users_directory_response_issues_total`** — Lenient parsing of
  HTTP directory responses; fix the directory to return strict JSON booleans.
- **`keystone_mcp_rbac_policy_in_sync`** and **`keystone_mcp_rbac_policy_info`**
  — Replicas out of step after a policy edit without a shared volume.
- **`keystone_mcp_tool_call_attempts_total{tool="unknown"}`** — Clients calling
  unpublished tool names (often fuzzing or stale catalogs).

Correlate with audit streams `oauth_session` and `rbac_users_mutation` in
application logs.
