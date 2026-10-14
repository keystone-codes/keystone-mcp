# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/).

Public contracts and the deprecation rule: [docs/compatibility.md](docs/compatibility.md).

## [Unreleased]

### Added

- `keystone-mcp users admins` lists full administrators, management roles and their holders; exits 1 when there is no active full administrator.
- `keystone-mcp users grant-admin --role <name>` grants a named role that gives full administration. Without the flag, when the policy has no `administrator` role but exactly one role that gives full administration, that role is granted.
- `KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS`; metric `keystone_mcp_oauth_token_exchange_total`; audit event `oauth_session`.
- `KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES` (default 16 MiB), `KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES` (default 64 KiB), `KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS` (default 2000).
- Metric `keystone_mcp_admin_refusals_total`; audit field `actor_subject_type` on `rbac_policy_mutation`.
- `LoginIdentity.key_id` and `LoginIdentity.key_expires_at` (optional) for form providers that sign people in with a Keystone API key.
- `docs/clients.md` lists the client versions tested with this release and known
  client behaviour; `docs/clients-checklist.md` is the release check. The bug
  report template asks for the client and its version. The demo upstream has a
  progress tool and an elicitation tool.
- `KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP`; production warning for an `http://` users directory; metric `keystone_mcp_users_directory_response_issues_total`; OIDC option `email_verified_claim`.
- Production startup warning when dynamic client registration is open and no redirect hosts are listed; metric `keystone_mcp_oauth_client_evictions_total`.
- Metrics `keystone_mcp_api_key_verifications_total`, `keystone_mcp_api_key_cache_entries`, `keystone_mcp_api_key_cache_evictions_total`, `keystone_mcp_users_revision_bump_failed_total`.
- Optional directory protocol `ApiKeyIdIndex`.
- `KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` (default 25): in-flight requests get this long to finish after SIGTERM (was 2 s).
- The metrics path and `/internal/*` accept a `Host` that is an IP literal, so Prometheus can scrape each pod by its IP.
- Metric `keystone_mcp_upstream_items_rejected_total{namespace,kind,reason}`.
- Metric `keystone_mcp_upstream_input_rounds_exceeded_total{namespace}`.
- CI: the contract freeze gate now compares the public surface generated from the code — environment variables (found by AST), policy keys, CLI commands, plugin protocol signatures, built-in tool arguments, metrics and their labels — with a baseline generated from the `v0.5.0` tag.
- Startup warnings W8–W19 (`docs/environment.md#startup-warnings`).

### Changed

- Management roles: a role that reaches any built-in administration tool is a management role, and a person whose roles reach all of them is a full administrator — both derived from the active policy, whatever the role names. Only a full administrator can give or take away a management role, or change, block, unblock, log out, or manage API keys of an account that holds one.
- `resources/read` requires every RBAC name of the matching resources and templates in the URI's own namespace to be allowed.
- Service accounts get `forbidden` from every administration tool that changes state (`users_*`, `service_accounts_*`, `api_keys_*`, `policy_*`); reading stays available. `tools/list` no longer shows a caller the tools it will be refused for lack of an interactive sign-in.
- A refresh token whose session marker is missing is refused with `invalid_grant` instead of being renewed as an `api_key` session. The marker is now written in the same Redis transaction as the token pair.
- Access tokens of people carry `"subject_type": "human"`; a sign-in that resolves to a service-account subject is refused.
- `latest` moves only when the released version is the highest one; a patch to an older line no longer moves it back.
- List requests (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) count toward the per-identity rate limit. A throttled `prompts/get` returns a prompt error.
- `/readyz` reports `503` until startup has finished, also with RBAC off; internal callers see `checks.bootstrap` (`pending`, `ok`, `fail`).

- Upper bounds on the next major version of `starlette`, `pydantic`, `redis`, `sqlalchemy`, `alembic`.
- Redis clients use 5 s connect and read timeouts and a 30 s health check; a hung Redis now fails requests instead of holding them.
- The container healthcheck reads `.env` and `KEYSTONE_MCP_HOST`.
- Startup errors (settings, upstream registry, policy file, users directory) are reported in one line.
- CLI commands ignore invalid settings they do not use and say so.

### Deprecated

- `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` keys that name the upstream's own tool name (deprecated since 0.6.0; use the published name).
- JSON log lines are compact (`"stream":"access"`, no spaces); field names are
  unchanged.
- A `FORWARDED_ALLOW_IPS` line in `.env` is reported as ignored.

### Fixed

- OAuth refresh now keeps the access token `subject_type` aligned with the session subject.
- An upstream's `serverInfo` stamp no longer reaches the client in tool and prompt results.
- `service_accounts_list`, `service_accounts_add` and `service_accounts_update` work when called over MCP.
- The HTTP port opens right after the users-directory migrations; upstream discovery, login provider warm-up (now in parallel) and policy loading run in the background, so a hanging upstream no longer keeps the port closed long enough for a liveness probe to restart the pod.
- A replica that changes a user or service account forgets its own cached decisions at once, even when Redis could not record the change.

- Host install (`docs/deploy.md`, `scripts/deploy.sh`): install straight into `/opt` without editable mode; `deploy.sh` deploys a tag (`DEPLOY_REF`), refuses a directory without git and waits for `/readyz`.
- With `KEYSTONE_MCP_LOG_FORMAT=json`, stderr contains only JSON lines: no
  FastMCP banner, uvicorn and FastMCP messages and tracebacks go through the
  Keystone formatter and redaction.
- `initialize` reports the Keystone version in `serverInfo.version`.
- `.env`: a quoted value followed by a comment no longer keeps its quotes; an
  unterminated quote is refused with the line number.
- A resource, resource template or prompt that an upstream renames, edits or removes after startup no longer makes the reconciler mark the whole namespace unavailable (which, with `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true`, failed `/readyz` on every replica).
- A failed `prompts/list` or `resources/list` keeps the previous prompts or resources instead of counting as an empty list.
- Policy validation of a prompt from an upstream with `strip_prefix` uses the name clients see; removing such a prompt upstream no longer crashes the refresh.
- `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` keys are matched against the published tool name, as documented.
- Tools whose `inputSchema` uses `x-mcp-header` can be called on MCP 2026-07-28 upstreams.
- `docs/compatibility.md` matched to the code: `KEYSTONE_MCP_ENV_FILE` is listed; `KEYSTONE_MCP_USERS_SERVICE_*` are not deprecated; the policy `version` is any non-empty string; `/login/<provider>` and `/login/redirect-not-allowed` are listed; `users import` never had `--email`; `catalog export` has no `--live-url`.

### Security

- keystone-mcp no longer re-validates an upstream's tool result against the upstream's own `outputSchema` on its event loop, so a pathological schema can no longer stall the whole process (including `/healthz`).
- Upstream answers, catalogs and tool schemas are bounded: `KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES`, `KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS`, `KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES`.
- Refresh-token rotation is atomic: a refresh token is exchanged at most once. A second exchange within `KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS` (default 10 s) gets the same response; a reuse after that revokes every token of that person at that OAuth client and is audited (`oauth_session`). Reusing an authorization code returns `invalid_grant` and revokes the tokens issued from it.
- Release images are scanned by Trivy per platform (amd64 and arm64) on the exact digest that is then tagged; base images are pinned by digest and updated by Dependabot.
- The HTTP users directory's `resolve` answer is checked strictly: a non-boolean `exists`, `is_blocked` or a non-string role is treated as the directory being unavailable instead of granting access. `0`/`1` are still accepted with a warning; a missing `is_blocked` is read as `false` with a warning.
- A sign-in e-mail whose characters become ASCII letters only after lower-casing or Unicode normalisation is refused.
- An OIDC provider with `email_claim` other than `email` must name the claim that confirms it (`email_verified_claim`) while `require_email_verified` is on.
- Dynamic client registration limits client metadata (request ≤ 16 KB, `client_name` ≤ 100 characters, ≤ 10 `redirect_uris` of ≤ 2 KB, unlisted RFC 7591 fields dropped); a client that never completes a sign-in expires after 24 hours; at `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` the oldest unused client is evicted instead of refusing everyone; IPv6 registration attempts are counted per /64.
- `/readyz` shows per-check details only when the caller's address is internal and its `Host` header is allowed.
- An upstream that keeps asking for input can no longer hold a tool call (and keystone-mcp's CPU) forever: at most 10 rounds per call, all within the tool timeout.
- Boolean settings accept `1/true/yes/on` and `0/false/no/off` in any case; any other non-empty value refuses startup instead of being read as false.
- In `production`, an API-key sign-in provider is refused next to any interactive sign-in provider, including one from a plugin.

### Migration

- Upstream resources and templates whose URI has no `scheme://` part are no longer published (a startup warning names each one). Give them a scheme, e.g. `file:///…` or `myapp://…`.
- A read of a URI that matches several templates of one upstream now needs all of their names allowed; add the missing names (or a glob such as `ns_*`) to roles that read such URIs.
- A tool whose schema exceeds 64 KiB, has a `pattern` longer than 512 characters or nests deeper than 64 levels is no longer published (warning and metric); raise `KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES` if needed.
- An upstream with more than 2000 tools (or prompts, resources, templates) keeps its previous catalog; raise `KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS`.
- Discovery no longer follows HTTP redirects (proxied calls never did); point the registry `url` at the final address.
- Host installs from 0.5 docs: reinstall with `uv sync --locked --no-dev --no-editable` in the deployed checkout and change `ExecStart` to `.venv/bin/python -m keystone_mcp.server`. `scripts/deploy.sh` now stops when run outside a git clone; set `DEPLOY_REF` to the release tag.
- Before upgrading, list who holds management roles: run `keystone-mcp users admins` on the new version (before switching traffic) — it lists full administrators, management roles and their holders. People in delegated roles (for example `users_*` only) keep managing ordinary accounts but get `forbidden` on management roles and their holders. If your administrator role is not named `administrator`, recovery is `keystone-mcp users grant-admin --email … [--role <name>]`.
- A client that reuses an old refresh token more than `KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS` after rotating it now loses its session (the person signs in again). While 0.5.x and 0.6.0 replicas run side by side, a token rotated by a 0.5.x replica is not recognised as reused; detection holds once every replica runs 0.6.0. Rolling back to 0.5.x restores the old 60-second behaviour; nothing is lost.
- Automation that changed users, service accounts or API keys through MCP with a service-account key now gets `forbidden`; do it from a person's session or with the `keystone-mcp` CLI on the host.
- Sessions opened on 0.4.x/0.5.x keep working after the upgrade. Rolling back to 0.5.x keeps sessions opened on 0.6.0: 0.5.x ignores the new marker fields. While replicas of both versions run side by side, a session renewed by a 0.5.x replica loses the new fields again; session max-age and key checks apply once every replica runs 0.6.0.
- Each list request now uses one slot of `KEYSTONE_MCP_THROTTLE_MAX` (default 120 per 60 s). If a client lists very often, raise the limit. Metric series for names that are not published are now reported as `tool="unknown"`.
- Startup refusals (`KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true` with an unavailable upstream, an invalid policy) still exit with code 1 and the same message, but after `/healthz` has started answering — rely on `/readyz`, not on the port being open, to know the replica is ready.
- An HTTP users directory that answers `exists`/`is_blocked` with strings stops working — return JSON booleans. A providers file with `email_claim` other than `email` and `require_email_verified` on fails to load until `email_verified_claim` is set (or `require_email_verified: false` with `allowed_domains`). Run `keystone-mcp config check` before upgrading.
- A client that registered but did not sign in within 24 hours registers again on its next attempt (MCP clients do this on `invalid_client`). Client metadata fields other than the RFC 7591 ones Keystone uses (`logo_uri`, `tos_uri`, `policy_uri`, `contacts`, `jwks`, `jwks_uri`) are no longer stored.
- Shutdown now waits up to 25 s: give the container at least 35 s to stop (`terminationGracePeriodSeconds`, `stop_grace_period`, `docker stop -t`).
- If a log pipeline matched JSON text with spaces (`"stream": "access"`), match
  the field instead (`jq`) or drop the space. A `.env` value with an
  unterminated quote now stops startup.
- Policy validation now knows a prompt of an upstream with `strip_prefix` by the name clients see (`hello_summarize`), so an exact allow rule for that name works. The stripped form 0.5.0 validated (`hello_marize`) is still accepted by validation but, as before, grants nothing — replace it with the visible name.
- An upstream that asks more than 10 questions in one tool call now gets `cancel` (handshake protocol) or the call fails (`kept requesting input`, MCP 2026-07-28).
- If you keyed `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` by the upstream's tool name, it keeps working; a startup warning names the published key to switch to.
- `KEYSTONE_MCP_*` booleans: replace values other than 1/true/yes/on/0/false/no/off; an empty value still means false but is now reported.
- Startup refuses a non-positive `KEYSTONE_MCP_TOKEN_TTL`, `_AUTH_CODE_TTL`, `_REFRESH_TOKEN_TTL`, `_LOGIN_PENDING_TXN_TTL`; a `KEYSTONE_MCP_PORT` outside 1–65535; a `KEYSTONE_MCP_BASE_URL` without an http(s) scheme or host; an empty or invalid `KEYSTONE_MCP_LOG_REQUEST_ID_HEADER`; with metrics on, a `KEYSTONE_MCP_METRICS_PATH` without a leading "/" or equal to `KEYSTONE_MCP_HTTP_PATH`. None of these worked before.
- `KEYSTONE_MCP_REDIS_URL` is checked at settings time in every RBAC mode (it was already required to start).
- A plugin sign-in provider with `interactive=True` next to `api_key` in `production`: move people to the interactive provider; machines keep Bearer keys.

## [0.5.0] - 2026-10-13

### Added

- CI: contract freeze gate — a frozen environment variable, policy key or CLI command cannot disappear without a `Removed` entry in the changelog.
- `docs/compatibility.md`: public contracts frozen since 0.5.0, what counts as a breaking change, deprecation rule, supported versions.
- Upstream resources and resource templates are published (URIs get the namespace, `scheme://<namespace>/...`) and authorized by `<namespace>_<name>` with the same allow patterns as tools.
- Contract tests for sign-in providers and users directories (`pytest -p keystone_mcp.contract_tests`, extra `contract-tests`) and a plugin template in `examples/plugin-template`.
- HTTP upstream elicitation forwarding (`KEYSTONE_MCP_PROXY_ELICITATION`, default
  `true`): form-mode `elicitation/create` and MCP 2026-07-28 `input_required`
  guard rounds reach the Keystone client with a `[namespace]` message prefix;
  URL-mode asks are declined. Metric `keystone_mcp_upstream_elicitations_total`.
- Upstream prompts are published as `<namespace>_<name>` under the same RBAC allow patterns as tools; `notifications/prompts/list_changed` after a change.
- `keystone-policy-admin` skill and `docs/policy-admin.md`: changing roles and allow patterns from the agent.
- OAuth token revocation endpoint `POST /revoke` (RFC 7009); revoking a refresh token also revokes that client's access tokens for the user. CLI `keystone-mcp users block|unblock|logout`.
- Plugins: sign-in provider types and users directories are discovered through the `keystone_mcp.login_providers` and `keystone_mcp.user_directories` entry points; built-in implementations use the same mechanism. `keystone-mcp plugins list`. `KEYSTONE_MCP_USERS_BACKEND_CONFIG`.
- `policy_*` tools (`policy_read`, `policy_catalog`, `policy_validate`, `policy_role_set`, `policy_role_delete`, `policy_allow_add`, `policy_allow_remove`, `policy_list_set`, `policy_rollback`): administrators change the RBAC policy from the agent; every change is validated against the live catalog, written atomically, reloaded in place and audited. Namespace `policy` is reserved.
- API keys stored in the users directory (hashed, shown once): `api_keys_issue|list|revoke` tools and `keystone-mcp keys` CLI. Service accounts call MCP with `Authorization: Bearer <key>`.
- `users_logout`; blocking a user revokes all of their tokens immediately.
- Service accounts (`svc:<name>`) with their own roles; `service_accounts_list|add|update` tools and `keystone-mcp service-accounts` CLI (built-in directory).
- Upstreams receive `X-Keystone-Subject` and `X-Keystone-Subject-Type`.
- Architecture decision records 0007–0012: login providers, API keys and service
  accounts, plugins via entry points, fastmcp major version, RBAC for prompts
  (resources when shipped), unsandboxed stdio upstreams; plus 0001–0006 (built-in
  users directory, roles in the policy file, signed identity assertion, Redis,
  dynamic client registration, no file API in the core).
- Startup refuses a removed variable that would change security behaviour
  if ignored, and warns about other removed variables
  (`docs/environment.md#removed-variables`).
- `UserDirectory` protocol (`keystone_mcp.user_directory`): one interface for
  reading and administering people; `users_*` tools work over any
  implementation. See `docs/user-directory.md`.
- Signed identity assertion for upstreams: registry `auth.identity_secret_env`;
  header `X-Keystone-Identity` (JWT HS256, audience = registry entry name)
  with subject, roles used by RBAC, auth method, OAuth client and task id.
- ES256 identity assertions (`auth.identity_alg: ES256`,
  `KEYSTONE_MCP_IDENTITY_SIGNING_KEY`) with the public key at
  `/.well-known/keystone-identity-jwks.json`.
- Reference verifiers for `X-Keystone-Identity` (Python, TypeScript) in
  `examples/keystone-identity/`; the demo upstream (`hello-upstream`) verifies
  the assertion and rejects forged headers once `HELLO_IDENTITY_SECRET` is set.
- Upstream registry: `transport: stdio` with `command`, `args`, `env`
  (names of keystone-mcp variables, never their values) and `cwd`; a
  supervised child process with restart backoff (1 second doubling to 60).
- stdio upstreams are discovered, proxied (with progress, cancellation and
  the identity assertion in `_meta`), supervised and restarted; `/readyz`
  lists upstream state for internal callers; metric
  `keystone_mcp_upstream_process_restarts_total`; the demo includes a stdio
  upstream.
- `notifications/tools/list_changed` is sent to open sessions and
  `subscriptions/listen` streams after a catalog change, a policy reload or
  a users-directory change.
- Progress notifications from upstream tools reach the client
  (`notifications/progress`), when the client asked for progress.
- A client cancellation or a keystone-mcp tool timeout is forwarded to the
  upstream request.
- Published on PyPI as `keystone-mcp-gateway` (same version as the image);
  `keystone-mcp serve` starts the server; the package ships type information
  (`py.typed`).
- `PolicyStore`: the RBAC policy file can be changed from inside the process
  with the same validation as a hot-reload, an atomic write, one backup
  (`<policy>.bak`), an in-place reload and an `rbac_policy_mutation` audit
  event. `KEYSTONE_MCP_POLICY_TOOLS` (`full` | `read-only` | `off`).
- Sign-in with any OpenID Connect provider (Okta, Microsoft Entra ID, Keycloak,
  Google) configured in `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`.

### Changed

- Sign-in, consent and error pages are rendered by one built-in template: card layout, light and dark theme, RTL for Hebrew and Arabic, mobile width, keyboard and screen-reader friendly; the redirect destination and the phishing warning are visually prominent. A language switcher (EN, RU, HE, AR) remembers the choice in a `km_lang` cookie for the whole sign-in. New `KEYSTONE_MCP_LOGIN_BRAND` sets the name shown on the pages.
- Production and demo compose examples mount the policy file read-write from a `policy/` directory so the `policy_*` tools can write it.
- `X-Author-Email` is sent only for people.
- Documentation brought in line with the 0.4.0 code: the Host/Origin
  allowlist and /metrics, deployment profile rules P5 and W5, the
  Kubernetes and Prometheus examples, client redirect hosts, host install
  permissions, and the supported-versions table in SECURITY.md.
- README states what Keystone-MCP does not do: multi-tenancy, an admin UI,
  storing business data, routing by request content.
- Tool-call metrics record `outcome="cancelled"`.
- Runtime moved to FastMCP 4.1 and MCP Python SDK 2. Clients that support MCP
  2026-07-28 negotiate it; older clients keep the handshake protocol. No
  configuration changes; OAuth clients and sessions stored in Redis remain
  valid.
- Idle HTTP sessions of the handshake protocol now close after 30 minutes
  (FastMCP default); clients reconnect transparently.
- Developers: the test suite runs without reruns; `pytest-rerunfailures` removed.
- Developers: sign-in goes through the `LoginProvider` protocol
  (`keystone_mcp.login`); Google and API-key sign-in are its first two
  implementations. No user-visible change.
- With `KEYSTONE_MCP_USERS_BACKEND=http`, `users_*` errors use the documented
  codes: `validation_error` instead of `invalid_role`, `conflict` instead of
  `user_already_exists`.
- With `KEYSTONE_MCP_USERS_BACKEND=http`, the roles passed to `users_add`,
  `users_set_roles` and `users_grant_role` are checked against the active
  RBAC policy before the directory is ever called; a directory that cannot
  be reached reports the fixed message "users directory is unavailable"
  instead of connection details.
- A read-only directory publishes only `users_list`.
- Developers: release workflow builds and checks the wheel and sdist and
  refuses a version already on PyPI.
- Developers: `register_catalog()` takes `directory=` (a `UserDirectory`)
  instead of `users_store=`; `UsersAdminAdapter.__init__` takes `directory=`
  instead of `(client_factory, users_store)`.
- CI guards against test reruns and forced test ordering.
- Upstream namespace validation no longer reserves `create` or `get`: with
  the built-in file tools gone, `users` is the only namespace a new upstream
  cannot shadow.
- `WebhookAdapter` and `ExternalHttpAdapter` moved to
  `keystone_mcp.contrib.adapters`. The webhook adapter reads
  `KEYSTONE_MCP_CONTRIB_WEBHOOK_*` when it is constructed; it has no default
  base URL.
- `requires_human_identity` accepts any interactive sign-in provider, not
  only Google. Access tokens carry an `interactive` claim.
- Login page error texts are provider-neutral.
- New Redis keys `km:oauth:subject:<sub>` (set) and `km:oauth:subject_nbf:<sub>`
  under `KEYSTONE_MCP_REDIS_KEY_PREFIX`; access tokens carry `iat`.
- `Pattern` members renamed: `M_B` → `SYNC`, `M_E` → `CONTINUATION`; `M_D` and `M_U` removed with the file tools. The built-in answer format is called the status envelope throughout the code and docs.
- Production profile: service accounts authenticate with Bearer API keys issued
  on the server (`keystone-mcp keys issue`); the `api_keys_issue` tool is not
  published, and API-key sign-in for people is refused while an interactive
  login provider is configured.

### Deprecated

- `KEYSTONE_MCP_GOOGLE_*`, `KEYSTONE_MCP_ENABLED_LOGIN_METHODS`,
  `KEYSTONE_MCP_PRIMARY_LOGIN_METHOD` — deprecated since 0.5.0, kept until the
  next major version; use a login providers file.

- `UserDirectoryBackend` (single `resolve_user` method) — implement
  `UserDirectory`; deprecated since 0.5.0, removed in 2.0.
- `X-Author-Email` is unsigned and deprecated since 0.5.0, removed in 2.0;
  verify `X-Keystone-Identity` instead.

### Removed

- `KEYSTONE_MCP_RBAC_ENABLED`. Use `KEYSTONE_MCP_RBAC_MODE`.
- The placeholder adapters `det_internal` and `chat_attachment`, and
  `KEYSTONE_MCP_DET_INTERNAL_URL`. Neither adapter was registered by default.
- Built-in file tools `create_upload_url` and `get_download_link`, the file
  API adapters (`keystone_mcp.adapters.upload_url`, `keystone_mcp.adapters.file_ref`,
  `keystone_mcp.storage`) and `KEYSTONE_MCP_FILE_API_URL` (startup is refused
  while it is set). File transfer is an upstream service like any other.
- `KEYSTONE_MCP_WEBHOOK_BASE_URL`, `KEYSTONE_MCP_WEBHOOK_CLIENT`,
  `KEYSTONE_MCP_WEBHOOK_PROJECT`, `KEYSTONE_MCP_WEBHOOK_API_TOKEN`,
  `KEYSTONE_MCP_LONG_POLL`.
- `KEYSTONE_MCP_AUTH_SERVICE_URL`, `KEYSTONE_MCP_AUTH_SERVICE_TOKEN` and the
  external key check; startup refuses while they are set.
- `keystone_mcp.auth.IdentityProvider` and `build_server(identity_provider=...)`;
  use `keystone_mcp.login` providers.

### Security

- Production startup and server build now treat api_key sign-in as configured only
  when the login providers file lists `api_key`, not from the deprecated
  `KEYSTONE_MCP_ENABLED_LOGIN_METHODS` default when a providers file is set.
- API key verification cache and the login form no longer accept a cached human
  key after its `expires_at`; positive cache TTL is capped to the key's remaining
  lifetime.
- API key secrets are stored and logged only as hashes or redacted forms
  (`ksk_<key_id>_***`); startup refuses legacy `KEYSTONE_MCP_AUTH_SERVICE_*`.
- stdio upstreams run as the keystone-mcp user without a sandbox; production
  profile warns at startup.
- Trivy image scan now blocks pull requests and releases on fixable HIGH and
  CRITICAL findings; temporary exceptions live in `.trivyignore` with a
  reason and a review date, checked by `tests/test_trivyignore.py`.
- A sign-in provider's own `provider` claim is no longer trusted for the
  issued token's `auth_method`: it is taken from the route (or form) the
  sign-in came back on, and a provider reporting another name is refused.
  Closes a path where a non-Google provider could report `provider="google"`
  and pick up the interactive-human gate's trust in that name.
- A deployment that configures any sign-in provider other than the built-in
  API-key form now gets the users-directory check wired up automatically, the
  way Google already did; previously only `google_login_enabled` triggered
  it, so a custom provider's directory check silently never ran for a form
  provider, and a custom redirect provider's callback always failed with 503.
- A redirect provider's `begin()` rejecting or raising now returns a sign-in
  error page (400 or 503) instead of an unhandled 500.
- Refreshing a session opened through a sign-in provider that is no longer
  configured is refused.
- OIDC discovery endpoints must share the configured issuer origin; login
  providers YAML parse errors no longer echo file contents; unverified email
  without domain restriction is rejected at config load.
- Token rotation and authorization-code exchange refuse credentials issued at
  or before a subject not-before timestamp, atomically with the write, so a
  refresh started before session revocation cannot mint a live pair afterward.
- `users_block` returns `service_unavailable` when session revocation fails
  after the directory block succeeds, so a retry can revoke tokens.

### Migration

- To use the `policy_*` mutation tools, mount the policy file (and its directory) read-write; otherwise they answer `policy_readonly`. With several replicas and no shared volume, set `KEYSTONE_MCP_POLICY_TOOLS=read-only` on all but one.
- Database migration `0003_api_keys`. Deployments that checked keys with an
  external service: issue new keys from the built-in directory and remove the
  two variables; external HTTP directories do not support API keys.
- Tokens issued before the upgrade are indexed on first use; a block revokes
  them in any case. If you share Redis, reserve these key patterns.
- Forks that pass `pattern=Pattern.M_B` (and the others) to `add_route`: use the new member names.
- Google users: nothing to do now; when convenient, move the Google settings into
  a login providers file (`type: google`). The Google redirect URI stays
  `<base>/login/google/callback`.
- Database migration `0002_service_accounts` runs at startup. Accounts like
  `bot@…` created as people keep working; move them to service accounts to get
  correct audit and human-only checks.
- Replace `KEYSTONE_MCP_RBAC_ENABLED=true` with `KEYSTONE_MCP_RBAC_MODE=enforce`;
  delete the old variable — the server does not start while it is set.
- A fork that registered `DetInternalAdapter` or `ChatAttachmentAdapter` must
  keep its own copy of the class (see the 0.4.x source).
- If you used the file tools, expose your file service as an MCP server and
  list it in the upstream registry; remove `KEYSTONE_MCP_FILE_API_URL` from
  `.env` and the two tool names from your policy file.
- Forks that register webhook routes: import from `keystone_mcp.contrib.adapters`
  and rename the variables to `KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL`,
  `_CLIENT`, `_PROJECT`, `_API_TOKEN`, `_LONG_POLL_SECONDS`, or pass
  `WebhookSettings` to the constructor.
- Sessions opened before the upgrade keep working; a session whose provider
  was removed from the configuration must sign in again.

## [0.4.0] - 2026-10-11

### Highlights

- The users directory (people, roles, blocks) is now built into Keystone-MCP
  itself — no separate users-directory service to run or reach over HTTP.
  SQLite for local use, PostgreSQL for production, plus a CLI to import an
  existing external directory and to recover an administrator account.
- A new `KEYSTONE_MCP_DEPLOYMENT_PROFILE` (`local` | `production`, now
  defaulting to `production`) validates the whole configuration against one
  posture at startup instead of trusting a mix of individually-safe settings
  to add up to a safe deployment.
- Proxied tool calls pass the upstream's answer and schema through as-is by
  default; the 0.3.x `{state, tool, task_id, result}` envelope is now opt-in.
- Hardening across the OAuth/login flow: a Host/Origin allowlist on every
  HTTP route (DNS-rebinding protection), a consent screen before issuing an
  authorization code, and a non-root container image.
- Documentation reorganized around deployment paths (local compose, Docker
  Compose production, Kubernetes) with `docs/README.md` as the index.

### Migration

Steps for an operator upgrading an existing 0.3.x deployment, in the order to
apply them.

1. **Deployment profile defaults to `production`.** An installation that
   never set `KEYSTONE_MCP_DEPLOYMENT_PROFILE` now runs as `production`,
   which refuses to start unless: `KEYSTONE_MCP_RBAC_MODE=enforce`;
   `KEYSTONE_MCP_DEV_TOKENS` is empty; `api_key` sign-in (if enabled) has
   `KEYSTONE_MCP_AUTH_SERVICE_URL`/`_TOKEN` configured;
   `KEYSTONE_MCP_BASE_URL` is not a plain-`http` address on a publicly
   reachable host; and, with the built-in users backend, the users database
   is PostgreSQL, not SQLite. For a local/dev deployment, set
   `KEYSTONE_MCP_DEPLOYMENT_PROFILE=local` before starting — it relaxes all
   of the above and requires a loopback `KEYSTONE_MCP_BASE_URL` instead. See
   [`docs/environment.md`](docs/environment.md#deployment-profile) for every
   rule and its error message.

2. **Add your roles to the policy file before importing people.** A role can
   now be granted only if it is declared in the RBAC policy file
   (`administrator` is always accepted); the shipped default policy no
   longer includes a `member` role. If you use other role names, add them to
   your own policy file now — before step 3, which skips any person whose
   role is not in the policy.

3. **The users directory is now built in.** `KEYSTONE_MCP_USERS_BACKEND`
   defaults to `local`: Keystone-MCP stores people, roles and blocks itself
   (migrations run on startup; a PostgreSQL advisory lock serializes
   replicas) instead of calling an external directory service. If you were
   running an external directory:
   a. set `KEYSTONE_MCP_USERS_DB_URL` to a PostgreSQL URL (SQLite is
      refused under the `production` profile, see step 1);
   b. run `keystone-mcp users import --from-url <old directory URL> --policy
      <policy file> [--dry-run]` to copy people, roles and blocks —
      idempotent, safe to re-run; the source stays authoritative on every
      run, so a person's local change through `users_*` since the last
      import is overwritten again from the source, and a role the source
      does not have is dropped; a role not in your policy is skipped and
      logged (this is why step 2 comes first);
   c. check `users_list` looks right;
   d. stop the old directory service.
   If you'd rather keep the external directory for now, set
   `KEYSTONE_MCP_USERS_BACKEND=http` explicitly instead — and note that
   **if `KEYSTONE_MCP_USERS_SERVICE_URL` is already set and
   `KEYSTONE_MCP_USERS_BACKEND` is not, startup now refuses to run** rather
   than silently switching to an empty local database (which would deny
   every user under `enforce`); set the backend explicitly either way. See
   [`docs/users.md`](docs/users.md#moving-from-an-external-users-directory).

4. **First administrator and recovery.** `MCP_USERS_SUPERADMIN_EMAIL` (read
   by the old external directory) is replaced by
   `KEYSTONE_MCP_SUPERADMIN_EMAIL`, seeded idempotently into the built-in
   directory on startup. Locked out of every administrator account:
   `keystone-mcp users grant-admin --email <you>` (add `--create` if the
   users database does not exist yet; without it the command refuses rather
   than create a fresh, empty database by accident).

5. **DEV tokens now require a directory entry.** Signing in with a DEV token
   is refused unless the email is present in the users directory and not
   blocked; the email is lower-cased first. DEV tokens are also refused
   outright under the `production` profile regardless of RBAC mode (step 1).
   Add anyone who used to sign in this way via `users_add` or
   `KEYSTONE_MCP_SUPERADMIN_EMAIL`.

6. **The server reads `.env` itself.** `keystone-mcp` (server and CLI) now
   loads `.env` from the current working directory, or the file named by
   `KEYSTONE_MCP_ENV_FILE`, before reading any setting; a value already set
   in the process environment still wins. If an unrelated `.env` happens to
   sit in the working directory you start the server from, it is now read —
   move it or point `KEYSTONE_MCP_ENV_FILE` elsewhere if that is not what you
   want.

7. **`KEYSTONE_MCP_AUTH_SERVICE_URL` / `_TOKEN` are deprecated**, to be
   removed in 0.4.1; API keys are moving into the built-in users directory.
   No action needed yet beyond planning the move.

8. **Default tool-call limit raised from 30 to 120 per 60 s.** If you relied
   on the old, stricter limit, set `KEYSTONE_MCP_THROTTLE_MAX=30` explicitly.

9. **File tools are off by default.** `create_upload_url` and
   `get_download_link` are now published only when
   `KEYSTONE_MCP_FILE_API_URL` is set — there is no longer a fallback to
   `KEYSTONE_MCP_WEBHOOK_BASE_URL`. `create_upload_url` no longer accepts
   `intended_project_id` (it was unused).

10. **An unreachable upstream no longer blocks startup.** Reachable upstreams
    are proxied normally; an unreachable one is logged and retried on every
    refresh tick instead of refusing to start. To keep the old all-or-nothing
    behavior, set `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true`.

11. **Proxied answers are passed through as-is.** The `{state, tool,
    task_id, result}` envelope and its status mapping are no longer applied
    by default. If a client or skill expects that envelope, set
    `KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=true` to restore it.

12. **Refresh tokens and registered OAuth clients now expire in Redis.**
    Existing records written without a TTL get one the next time they are
    read; a record nobody reads again keeps no TTL. To find and clear them by
    hand: `redis-cli --scan --pattern 'km:oauth:rt:*'` and `redis-cli --scan
    --pattern 'km:oauth:client:*'`, then `TTL <key>` for each (`-1` means no
    TTL) — deleting one is safe: the person signs in again, and a deleted
    client registers again (with DCR off, re-run the manual registration).

13. **The container runs as a non-root user (uid/gid `10001`).** Any volume
    mounted into it — including the users-directory data directory — must be
    writable by that uid; `chown -R 10001:10001 <volume>` if it was created
    while the container still ran as root.

14. **Dynamic client registration can now be turned off.**
    `KEYSTONE_MCP_OAUTH_DCR_ENABLED` defaults to `true`, so no action is
    needed unless you want to disable `POST /register` and register OAuth
    clients manually instead; see
    [`docs/environment.md`](docs/environment.md#registering-a-client-manually).

15. **Compose files.** This release ships only `docker-compose.demo.yml`
    (local demo) and its `docker-compose.postgres.yml` overlay. If your
    0.3.x deployment was started from an earlier example compose file, move
    it to `examples/production/docker-compose.yml`; there is no separate
    users-directory container any more.

16. **`.env.example` was rewritten** as a local-profile section (it starts
    the server once `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` is filled in, and
    lets someone sign in once `KEYSTONE_MCP_DEV_TOKENS` and
    `KEYSTONE_MCP_SUPERADMIN_EMAIL` are set; `setup.sh` fills all three), a
    production-profile section listing what to change, and every remaining
    setting commented out. Compare it against your own `.env` — values you
    already set are unaffected except where this list says otherwise.

17. **A reverse proxy or load balancer in front of Keystone-MCP needs its own
    hostname allowed.** Every HTTP route now refuses a request whose `Host`
    header (and `Origin`, when present) is not on an allowlist built from
    `KEYSTONE_MCP_BASE_URL` plus `KEYSTONE_MCP_ALLOWED_HOSTS`. If something in
    front of Keystone-MCP forwards a different `Host` than
    `KEYSTONE_MCP_BASE_URL` — a load balancer's own hostname, an internal DNS
    name — add it to `KEYSTONE_MCP_ALLOWED_HOSTS` (comma-separated), or every
    request through it now gets `421`. The same applies to anything that
    reaches Keystone-MCP by another name: a Prometheus scrape of `/metrics`
    (e.g. `127.0.0.1:8080` on the same host, or a Kubernetes Service name)
    and `keystone-mcp catalog validate --live-url` /
    `python -m keystone_mcp.rbac.catalog` against
    `/internal/live-published-names`. Only `/healthz` and `/readyz` are
    exempt. A pod IP cannot be listed in advance, so scraping each pod by IP
    is refused.

18. **Upstream bearer-token variables must use one reserved name prefix.**
    An `auth.bearer_env` entry in `upstreams.yaml` must name an environment
    variable starting with `KEYSTONE_MCP_UPSTREAM_`, and must not reuse a
    name `config.py` already reads as a setting of its own (for example
    `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL`). Rename an existing entry and its
    variable to fit, e.g. `KEYSTONE_MCP_UPSTREAM_<NAMESPACE>_TOKEN`; startup
    now refuses anything else.

### Added

- `docs/clients.md`: connect Claude Code, Cursor and Claude Desktop, locally
  and over HTTPS.
- `tests/integration/test_setup_first_run.py`: end-to-end test of a
  brand-new deployment — `setup.sh --non-interactive --skip-install` in the
  `local` profile, a real server process started the way the script's own
  summary tells a new user to, `GET /healthz`, then the first administrator
  signing in over the real OAuth connector and seeing `users_list` among its
  published tools; a second sign-in for an email absent from the built-in
  users directory is refused with `403`.
- `KEYSTONE_MCP_DEPLOYMENT_PROFILE` (`local` | `production`, default
  `production`): tells the server which posture to validate its settings
  against. `local` requires a loopback `KEYSTONE_MCP_BASE_URL` and allows DEV
  tokens under any `KEYSTONE_MCP_RBAC_MODE`. `production` requires
  `KEYSTONE_MCP_RBAC_MODE=enforce`, refuses `KEYSTONE_MCP_DEV_TOKENS`
  outright, refuses `api_key` sign-in without an external key-verification
  service, and refuses a plain-`http` `KEYSTONE_MCP_BASE_URL` on a publicly
  reachable host. `server.main` logs the resolved profile and a set of
  startup warnings (`keystone_mcp.config.startup_warnings`) for
  risky-but-not-refused configurations. See
  [`docs/environment.md`](docs/environment.md#deployment-profile).
- `GET /readyz` readiness endpoint: Redis ping, active RBAC policy, built-in
  users database. `200` when every check is not `fail`, otherwise `503`.
  Check detail is shown only to internal callers (same source-address gate as
  `/metrics`); an external HTTP users directory
  (`KEYSTONE_MCP_USERS_BACKEND=http`) is deliberately not checked, so an
  unreachable external directory does not pull every replica out of rotation
  at once. The container `HEALTHCHECK` now polls `/readyz` instead of
  `/healthz`.
- Release workflow refuses a tag whose version differs from
  `pyproject.toml`, `__version__` or the latest CHANGELOG heading
  (`scripts/check_version.py`).
- Multi-arch images (`linux/amd64`, `linux/arm64`); release workflow starts
  the image against Redis before publishing and creates a GitHub Release
  from the CHANGELOG section (`scripts/extract_changelog.py`).
- `docs/environment.md`: rate-limit presets, running behind a reverse proxy
  (`FORWARDED_ALLOW_IPS`), and what changes with several replicas.
- Tests that keep `config.py`, `.env.example` and `docs/environment.md` in
  sync, and that check every relative link and heading anchor in the
  Markdown docs.
- Test upstream on the low-level MCP SDK (`tests/support/lowlevel_upstream.py`)
  and proxy tests against a non-FastMCP server.
- `keystone-mcp` (server and CLI) now read `.env` from the current working
  directory, or from the file named by `KEYSTONE_MCP_ENV_FILE`, before any
  setting is read; a value already set in the process environment always
  wins over the file.
- `KEYSTONE_MCP_OAUTH_DCR_ENABLED` (default `true`): toggle for dynamic
  client registration (RFC 7591, `POST /register`). When `false`, the route
  and the `registration_endpoint` metadata entry are both absent, and OAuth
  clients are registered manually; see
  [`docs/environment.md`](docs/environment.md#registering-a-client-manually).
- Built-in users directory module (`keystone_mcp.users`): SQLAlchemy models,
  Alembic migration, administrator invariants; SQLite and PostgreSQL.
- End-to-end test: OAuth bearer token, RBAC `enforce`, denied `call_tool`.
- `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL` (default `false`): refuse to start when
  any configured upstream is unreachable, instead of proxying the rest.
  Metric `keystone_mcp_upstream_available{namespace}` (1 = reachable).
- `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` (default `10000`): soft cap on the number
  of live (non-expired) registered OAuth clients. `POST /register` past the
  cap is refused with `invalid_client_metadata`; `0` disables the cap.
  Tracked via a Redis sorted-set index that also picks up legacy client
  records written before this change. New Prometheus metrics:
  `keystone_mcp_oauth_client_registrations_total{outcome}` and the
  `keystone_mcp_oauth_clients` gauge.
- `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` (default empty, no
  restriction): comma-separated bare hostnames a registered client's
  `redirect_uri` may point to, plus an optional `scheme://host` entry for a
  custom (non-http(s)) URI scheme. When set, `POST /register` refuses a
  client whose `redirect_uris` include a host outside the list, or whose
  `redirect_uris` is empty/`null` (`invalid_redirect_uri`), and both
  `/authorize` and token exchange (`POST /token`, authorization code and
  refresh token) refuse a client whose `redirect_uri` is not allowed —
  including one registered before the restriction was turned on or
  tightened, so it cannot keep refreshing its tokens forever on an allowance
  that no longer holds. `/authorize`'s refusal stays on this server
  (`/login/redirect-not-allowed`, a 400 page) instead of redirecting the
  browser to the client's own (disallowed) `redirect_uri` with an error. A
  bare host entry matches `https` for that host and `http` only for loopback
  (`localhost`/`127.0.0.1`/`::1`); a custom scheme is matched only against
  its own explicit `scheme://host` entry. New outcome
  `keystone_mcp_oauth_client_registrations_total{outcome="rejected_redirect_host"}`.
- `KEYSTONE_MCP_USERS_BACKEND` (`local` default, `http`),
  `KEYSTONE_MCP_USERS_DB_URL`, `KEYSTONE_MCP_SUPERADMIN_EMAIL`: the users
  directory is now built into the server by default — migrations run on
  startup (a PostgreSQL advisory lock serializes replicas), and the
  configured administrator is seeded idempotently.
  `KEYSTONE_MCP_USERS_BACKEND=http` keeps the external HTTP directory for
  forks.
- `keystone-mcp users grant-admin --email …` — restore administrator access
  on the server host (creates the account if missing, grants
  `administrator`, unblocks; `--create` is required to run it against a
  users database that does not exist yet).
- `keystone-mcp users import --from-url … [--token …] [--policy …]
  [--dry-run]` (the source token is prompted for when `--token` is omitted)
  — copy people, roles and block state from an external users directory. The
  source is authoritative on every run, including a second one: re-running
  restores a block or `administrator` grant/revoke the source still has,
  even if it was changed locally through `users_*` since the last import,
  and drops any role granted locally that the source does not have. Roles
  not in the policy are skipped and logged. `--dry-run` reports
  `admin_or_block_changes`, the count of existing people this would affect
  that way.
- Upstream registry entries accept `auth: {bearer_env: VAR}`; Keystone-MCP
  sends `Authorization: Bearer <value of VAR>` on discovery and every
  proxied call. Startup is refused if the variable is unset (and, see
  Security, if its name does not fit the reserved prefix).
- `docker-compose.demo.yml`: Keystone-MCP, Redis and a sample upstream
  (`examples/hello-upstream/`) in one command. `docker-compose.postgres.yml`
  overlay stores the users directory in Postgres.
- `docs/paths/production-docker.md` and `examples/production/`: a
  step-by-step Docker Compose path for production — a pinned image, Redis,
  Postgres as the users directory, Google sign-in, and TLS in front — plus
  upgrades, backups, and running more than one replica.
- CI runs the demo compose end to end: DCR, DEV-token login, `hello_*` call,
  `users_add`, role-filtered catalog (`scripts/smoke_demo.py`).
- `docs/paths/local-compose.md`: run the demo and try roles in about 15
  minutes.
- `docs/adding-routes.md`: what a fork can replace today (sign-in check,
  users directory, adapters, policy, schema patches) and what still needs a
  core change.
- Kubernetes example under `examples/kubernetes/` with readiness on
  `/readyz`: plain `kubectl apply -k examples/kubernetes/` manifests (no
  Helm, no templating) for a two-replica Deployment, ConfigMap (RBAC policy
  and upstream registry), Service, and example-only Secret and Ingress
  files. Runs non-root (uid/gid `10001`) with a read-only root filesystem.
  Redis and Postgres are not part of the example — bring your own.
  Walkthrough: [`docs/paths/kubernetes.md`](docs/paths/kubernetes.md).
  Checked with `kubectl kustomize` and `kubeconform:v0.6.7 -strict`; static
  checks in `tests/test_kubernetes_example.py`.
- CI: dependency audit (`uv audit`) on every PR and weekly; Trivy image scan
  (non-blocking).
- `KEYSTONE_MCP_ALLOWED_HOSTS`: extra names the new `HostGuardMiddleware`
  accepts on the `Host`/`Origin` headers, beyond `KEYSTONE_MCP_BASE_URL`'s
  own host and its loopback aliases — a load balancer's hostname, an
  internal DNS name. See Security below and
  [`docs/environment.md`](docs/environment.md).

### Changed

- README rewritten as a short pitch (what Keystone-MCP is, and the
  facade/router/authorization split), a one-command local demo, and a short
  "Why Keystone-MCP" list; the detailed Observability block, the "Users
  directory" and "Install" sections, and the 13-link documentation list are
  gone from it — their content already lives in
  `docs/observability-rbac.md`/`docs/observability-logging.md`,
  `docs/users.md`, `docs/deploy.md` and `docs/security-model.md`.
  `docs/README.md` is a new index of every guide grouped by role, and
  `docs/features.md` is a new page describing every capability in depth,
  including which ones are still planned for 0.5.0.
  `tests/test_doc_links.py::test_docs_index_links_every_page` keeps the
  index honest: a new page under `docs/` or `docs/paths/` without an entry
  there now fails the test.
- `production` refuses a SQLite users directory: when
  `KEYSTONE_MCP_USERS_BACKEND=local` (the default), startup now refuses an
  empty or `sqlite`-scheme `KEYSTONE_MCP_USERS_DB_URL`. SQLite is one file
  per replica — two replicas each write their own copy and roles drift
  apart, and the file is lost with the container unless a volume happens to
  be mounted on it — so `production` now requires Postgres. `local` still
  allows SQLite, and `KEYSTONE_MCP_USERS_BACKEND=http` is unaffected (the
  external directory manages its own storage). See
  [`docs/environment.md`](docs/environment.md#deployment-profile).
- `KEYSTONE_MCP_DEV_TOKENS` combined with `KEYSTONE_MCP_RBAC_MODE=enforce`
  is now a `KEYSTONE_MCP_DEPLOYMENT_PROFILE`-gated decision instead of an
  outright refusal: `local` allows the pair (with a startup warning), while
  `production` refuses DEV tokens under any RBAC mode. The former rule — DEV
  tokens with `enforce` refused unless an auth service was configured — no
  longer exists as a standalone check.
- Upstream namespaces are validated: allowed characters, no namespace that
  can shadow a built-in tool (`users`, `create`, `get`, …), and no namespace
  that is another namespace plus `_suffix`. Checked at startup, in
  `keystone-mcp upstream validate`, and for `KEYSTONE_MCP_UPSTREAMS`.
  Collisions that still slip through within one service (e.g. after
  `strip_prefix`) are caught at discovery time and logged as an ERROR
  instead of silently shadowing one tool with another.
- An unreachable upstream no longer blocks startup: reachable upstreams are
  proxied, the unreachable one is logged with its namespace and reason and
  retried on every refresh tick. Startup is refused only when every upstream
  is unreachable with RBAC on, or when
  `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true`.
- With RBAC on, allow patterns that belong only to an unavailable upstream
  namespace (`<namespace>_…`) are logged as not verified instead of refusing
  the policy; they are checked against the live catalog when the upstream
  comes up. An allow pattern with no owning namespace (a typo in the
  namespace part, or one matching nothing at all) still refuses startup as
  before. The bare `*` pattern matching nothing because the whole catalog is
  empty (no upstreams, file tools and `users_*` all off) is now a WARNING
  too, instead of refusing startup or failing `keystone-mcp catalog
  validate`.
- CI test matrix: Python 3.11, 3.12, 3.13.
- Dependabot uses the `uv` ecosystem; GitHub Actions bumped to current major
  versions.
- Default `KEYSTONE_MCP_THROTTLE_MAX` raised from 30 to 120 calls per 60 s
  per identity.
- Bounded the number of distinct `oauth_client_id` values reported on
  tool-call metrics: the first `KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT`
  (default 50) clients seen by a process keep their own label, further
  clients are reported as `other`, so an unbounded stream of OAuth client
  registrations cannot create an unbounded number of Prometheus series.
- `.env.example` rewritten as a single file with a local-profile section
  that starts the server, a production-profile section listing what to
  change, and commented-out optional settings for every remaining
  `config.py` variable, including four named rate-limit presets.
  `KEYSTONE_MCP_AUTH_SERVICE_URL` is commented out (empty) by default.
- Proxied answers are passed through as-is by default; the `{state, tool,
  task_id, result}` envelope and `status` mapping are opt-in via
  `KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=true`.
- `GET /login/google` no longer redirects straight to Google; it now
  bounces (`303`) to the consent screen at `/login?txn=…`, which is where
  the actual redirect to Google (`POST /login/google`) is initiated from.
- `KEYSTONE_MCP_USERS_SERVICE_URL` / `KEYSTONE_MCP_USERS_SERVICE_TOKEN` are
  required only with `KEYSTONE_MCP_USERS_BACKEND=http`.
- `create_upload_url` and `get_download_link` are published only when
  `KEYSTONE_MCP_FILE_API_URL` is set, and `filename` has no default (see
  Removed for the dropped `intended_project_id` parameter).
- The default policy has one role, `administrator`, and a commented example
  of a second role.
- `users_*` tools write to the built-in directory by default; HTTP proxying
  only with `KEYSTONE_MCP_USERS_BACKEND=http`. Tool names, arguments,
  response shape and error codes are unchanged.
- A role can be assigned only if it exists in the RBAC policy file
  (`validation_error`, `unknown role: <name>`); `administrator` is reserved
  and always accepted.
- CI runs the users-directory tests against PostgreSQL 16, in addition to
  SQLite: a `postgres:16-alpine` service in the `test` job, plus a dedicated
  "Users directory on PostgreSQL" step so a silent skip there fails the
  build. Added `tests/test_users_concurrency.py` (exactly one administrator
  survives when the last two are revoked or blocked at the same instant)
  and `tests/integration/test_users_admin_local_smoke.py` (full `users_*`
  lifecycle against the built-in directory, SQLite and PostgreSQL),
  replacing an older integration test that depended on a live external
  users-directory service that is no longer published.
- Diagrams show the built-in users directory and the upstream registry
  file.
- `setup.sh` no longer asks for an external users-directory URL or token
  (the users directory is built in). It now asks for a deployment profile
  first — `local` (token sign-in, SQLite, this machine only) or
  `production` (Google sign-in, Postgres, a public host) — then only the
  questions that profile needs, and writes `KEYSTONE_MCP_SUPERADMIN_EMAIL`
  instead of probing a directory service over HTTP. New flags:
  `--non-interactive` (every answer comes from a `KEYSTONE_SETUP_*`
  environment variable instead of a prompt; exits 2 with a message naming
  the variable when a required one is missing or invalid), `--skip-install`
  (skip `uv sync` / `pip install`), and `--help`. Writing `.env` replaces
  the value of an existing line in place (including a commented-out default
  in the `.env.example` production section) instead of ever appending a
  second line for the same variable.
- Proxied tools publish the upstream's input schema verbatim (descriptions,
  enums, bounds, nested objects, `$defs`), plus `outputSchema` (in
  transparent mode only), `title` and `annotations`. Required fields are no
  longer published as nullable. A parameter name that is not a legal Python
  identifier (`max-results`) or is a reserved keyword (`from`) no longer
  makes the whole tool unpublishable, since there is no Python function
  signature built from the schema anymore.
- `docs/deploy.md` now covers installing on a host with systemd and the
  built-in users directory; it no longer describes an external users
  service or Docker sidecars. Docker deployments are covered by
  `docs/paths/production-docker.md` instead.
- Docs: upstream services are configured with the registry file in every
  example; plain-http flags are described for internal networks; behaviour
  of unavailable services, built-in tools and the users directory updated.

### Deprecated

- `KEYSTONE_MCP_AUTH_SERVICE_URL` / `KEYSTONE_MCP_AUTH_SERVICE_TOKEN`:
  removal planned for 0.4.1; API keys move into the built-in users
  directory.

### Removed

- The 0.3.x example compose files (external-network example, end-to-end
  file, users-directory sidecar file), replaced by
  `docker-compose.demo.yml`, `docker-compose.postgres.yml` and
  `examples/production/`.
- The `member` role from the shipped default RBAC policy; only
  `administrator` ships now, with a commented-out example of a second role.
- `create_upload_url`'s unused `intended_project_id` parameter.

### Security

- Require PyJWT ≥ 2.15.1 and lock cryptography 50.x; earlier versions have
  published advisories affecting JWKS fetching and key handling.
- Refresh tokens and registered OAuth clients now carry a TTL in Redis: the
  client lives for `max(KEYSTONE_MCP_REFRESH_TOKEN_TTL, KEYSTONE_MCP_TOKEN_TTL)`
  plus one day, renewed on every token issued under it; the refresh token's
  TTL follows its own expiry (or `KEYSTONE_MCP_REFRESH_TOKEN_TTL` when none
  is set). A refresh token's sign-in-method marker is now kept for a short
  grace period (60s) after rotation instead of being deleted immediately:
  two concurrent requests refreshing the same token both used to validate
  it before either rotated it away, so the second request could reach
  token exchange after the first had already rotated and deleted the
  marker — previously that read nothing and silently fell back to
  `api_key`, downgrading a Google-authenticated session and losing its
  RFC 8707 resource binding.
- Per-IP rate limit on `GET`/`POST /authorize` and `POST /token`
  (`KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX`, default `120` per login throttle
  window), independent from the existing `/login`/`/register` limit.
- Login page (`/login`, `/login/google`) HTML responses now send
  `X-Frame-Options: DENY` and a `Content-Security-Policy` (`default-src
  'none'`, `frame-ancestors 'none'`) to prevent clickjacking via iframe
  embedding, plus `Referrer-Policy: no-referrer` and `Cache-Control:
  no-store`. The successful login redirect (`302`) is unaffected.
- Container runs as non-root user `keystone` (uid/gid 10001); `curl`
  removed from the runtime image.
- Consent screen on `/login`: before issuing an authorization code,
  Keystone shows which application is requesting access and the host it
  will redirect to, and requires an explicit click. Closes the attack
  where a client registers its own `redirect_uri` and sends a victim a link
  straight into an already-authenticated Google session. Google sign-in now
  starts with a button on this screen (a CSRF-checked `POST
  /login/google`) instead of a bare link, so it cannot be triggered by a
  direct URL or from inside an iframe. The round trip is bound to the
  browser that started it: `/login/google/callback` refuses to proceed
  unless the browser presents the same `km_login_csrf` cookie the consent
  screen set, closing a residual gap where an attacker could start their
  own `/authorize` and consent screen, submit `POST /login/google`
  themselves, and send a victim the resulting Google authorization URL. The
  cookie uses the `__Host-` prefix (`Secure`, `Path=/`) when
  `KEYSTONE_MCP_BASE_URL` is `https` — which a browser only stores for an
  exact-origin, `Secure`, `Domain`-free cookie — and keeps the unprefixed
  name (`Path=/login`) for a plain-`http` deployment (local/demo), where the
  prefix's `Secure` requirement would not be honest about what the browser
  actually enforces. The cookie value is also no longer reused from an
  incoming request — a fresh value is minted on every render of the consent
  screen, so re-rendering the same `?txn=` (a second tab, an invalid-token
  retry, a language switch) rotates it and a page already open elsewhere for
  the same transaction 400s on submit until reloaded.
- Token sign-in requires the email to exist in the users directory and not
  be blocked whenever a directory is consulted — RBAC `observe`/`enforce`,
  Google enabled, or DEV tokens configured. Only a `local`-profile
  deployment with RBAC `off`, Google off and the deprecated external
  API-key service skips the lookup. The email is lowercased before the
  authorization code is issued.
- Both the per-IP and per-email login-throttle tables are now bounded
  (periodic sweep of entries that have aged out of the window, a
  20000-entry cap, oldest-accessed evicted first; an email key is also
  truncated to 320 characters first). Previously a source address or email
  seen only once — trivial to produce in bulk, especially over IPv6, or by
  probing one login per address without ever repeating one — left a
  permanent entry behind, growing the table without bound.
- `GET`/`POST /authorize`: a client registered before
  `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` existed (or before it was
  tightened) could still trigger a browser redirect straight to its own
  disallowed-host `redirect_uri`, because an invalid `scope` (or a few other
  malformed fields) made the MCP SDK's own authorization handler redirect
  there before Keystone's own check ever ran. `/authorize` now resolves
  `client_id` and checks the client's registered redirect URIs against the
  allowlist before the SDK handler runs at all; a disallowed client is sent
  to `/login/redirect-not-allowed` instead, the same safe destination the
  existing check already used.
- `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` accepts an IPv6 literal
  (`::1`, bracketed `[::1]`, or any other IPv6 address) as an entry — it
  used to refuse any entry containing `:`, which caught IPv6 literals along
  with the port/scheme mistakes that check exists for. Entries are
  normalized to the bracket-free, compressed form (`::1`), matching what
  the existing loopback check compares against.
- The public/private host check recognizes a legacy decimal/hex/octal IPv4
  literal (`134744072`, `0x08080808` — both `8.8.8.8`, what a browser or
  `curl` actually connects to) as the address it is, instead of falling
  through to the bare-name rule and being classified private. An
  internal-looking DNS name (`*.svc.cluster.local`, `*.internal`) is still
  classified public, deliberately: a suffix convention is not a trust
  boundary, so `production` still refuses a plain-`http`
  `KEYSTONE_MCP_BASE_URL` on one — only the error message changed, to
  explain that a closed-cluster install needs a TLS-terminating proxy in
  front of it too. New startup warning: `local` profile,
  `KEYSTONE_MCP_HOST` unspecified (`0.0.0.0`/`::`) and
  `KEYSTONE_MCP_DEV_TOKENS` set — not a refusal (the Docker demo
  legitimately binds `0.0.0.0` inside its container), but anyone who can
  reach the port signs in as any directory member.
- **DNS rebinding.** Every HTTP route — every OAuth endpoint (`/register`,
  `/authorize`, `/login`, `/token`, `/.well-known/*`) and `/mcp` itself —
  now refuses a request whose `Host` header (and, if present, `Origin`) is
  not on an allowlist built from `KEYSTONE_MCP_BASE_URL` (plus
  `localhost`/`127.0.0.1`/`[::1]` when that host is loopback) and the new
  `KEYSTONE_MCP_ALLOWED_HOSTS` (`HostGuardMiddleware`,
  `src/keystone_mcp/http/host_guard.py`). fastmcp 3.4.4 ships its own
  Host/Origin guard, but it defaults to off and, even enabled, cannot
  exempt a route — which `/healthz`/`/readyz` need, since a container
  healthcheck or a Kubernetes probe reaches them by an address
  (`127.0.0.1`, or a pod IP assigned at pod start) that cannot be
  enumerated ahead of time; both are exempted here instead. A disallowed
  `Host` is refused with `421`; a disallowed `Origin` with `400`. Without
  this, a page on an attacker-controlled hostname could rebind its DNS to
  `127.0.0.1` after loading and drive the whole OAuth flow — register a
  client, `/authorize`, `POST /login` with a DEV token, `/token`, call any
  published tool — from inside a victim's own browser, past any
  network-level isolation.
- `UpstreamRegistry._auth_headers` (the per-namespace `Authorization:
  Bearer …` headers set via `auth.bearer_env`) no longer appears in
  `repr(UpstreamRegistry)`, nor transitively in `repr(SurfaceReconciler)`
  (which holds an `UpstreamRegistry`). Logging or printing either object —
  e.g. in a traceback — could previously leak an upstream bearer token in
  clear text.
- An upstream registry entry's `auth.bearer_env` must now start with the
  reserved `KEYSTONE_MCP_UPSTREAM_` prefix, and must not name one of the
  `KEYSTONE_MCP_UPSTREAM_*` variables `config.py` itself already reads as a
  setting (`ALLOW_INSECURE_HTTP`, `EGRESS_ALLOW_PRIVATE`,
  `DISCOVERY_RETRIES`, `DISCOVERY_TIMEOUT`, `REQUIRE_ALL`,
  `TOOL_TIMEOUT_SECONDS`, `TOOL_TIMEOUTS`). Previously only the
  variable-name *shape* was checked, so anyone editing `upstreams.yaml`
  could write `bearer_env: KEYSTONE_MCP_GOOGLE_CLIENT_SECRET` (or any other
  secret Keystone-MCP already holds) next to a `url` of their choosing, and
  Keystone-MCP would send that secret to that upstream as a bearer token.
- `setup.sh` rejects any `KEYSTONE_SETUP_*` value (interactive or
  `--non-interactive`) that contains a newline or other control character,
  before anything is written: the `.env` writer splices each value into its
  line verbatim, so an embedded `\n` could otherwise inject extra
  `KEYSTONE_MCP_*` assignments past the fields setup.sh itself means to set
  (for example smuggling `KEYSTONE_MCP_RBAC_MODE=disabled` in through
  `KEYSTONE_SETUP_BASE_URL`). An injection attempt exits `2` and leaves an
  existing `.env` untouched.
- `setup.sh` creates `.env` at mode `0600` from its very first byte (via a
  scoped `umask 077` around the copy, or a `chmod 600` on an existing file,
  before anything is written into it) instead of relying on a final `chmod
  600` after the file had already been created at the process's default
  mode (typically `0644`) with the administrator's secrets already written
  into a group/other-readable file.
- `setup.sh` no longer echoes `KEYSTONE_SETUP_USERS_DB_URL`'s password to
  stderr when it does not start with `postgresql+psycopg://`; the error now
  shows the URL with its credentials replaced by `***`.
- `.github/workflows/ci.yml` and `release.yml` now declare a top-level
  `permissions: contents: read`, so a job added later without its own
  `permissions:` block no longer inherits a broader default token scope;
  `release.yml`'s `publish` (`packages: write`) and `github-release`
  (`contents: write`) jobs keep their own wider grants. Every third-party
  action across all four workflow files (`actions/checkout`,
  `astral-sh/setup-uv`, `actions/upload-artifact`, `docker/setup-qemu-action`,
  `docker/setup-buildx-action`, `docker/build-push-action`,
  `docker/login-action`, `docker/metadata-action`, `aquasecurity/trivy-action`)
  is now pinned to the commit SHA of its current tag (each with a `# v…`
  comment naming the tag it was pinned from) rather than the tag itself, so
  a tag cannot later be moved to point at different code;
  `.github/dependabot.yml` already tracks the
  `github-actions` ecosystem and will open PRs that advance these pins.
- `examples/kubernetes/`: `configmap.yaml`'s `upstreams.yaml` advised a
  plain `ClusterIP` Service for an upstream with no further isolation,
  which left any other pod in the cluster free to call it directly and
  send a forged `X-Author-Email`, impersonating any user. Added
  `networkpolicy.example.yaml` (not applied by `kustomization.yaml`, same
  as `secret.example.yaml`/`ingress.example.yaml`) restricting an
  upstream's ingress to Keystone's own pods, and a new section in
  [`docs/paths/kubernetes.md`](docs/paths/kubernetes.md#protecting-an-upstream-from-pod-to-pod-spoofing)
  covering both mitigations — `NetworkPolicy` and `auth.bearer_env` — and
  why using both is stronger than either alone.

### Fixed

- Signing in from the login page failed with `400 Forbidden Origin`: the page
  sends `Referrer-Policy: no-referrer`, so the browser posts the form with
  `Origin: null`. The Host/Origin guard now treats `Origin: null` as absent;
  the `Host` check still applies.
- Proxied tools whose input schema lists an optional field before a
  required one are published instead of failing discovery of the whole
  upstream. A tool that cannot be published is skipped with an ERROR log;
  the rest of the namespace is still proxied.
- The background catalog refresh no longer stops when an upstream is
  unreachable; any per-upstream error keeps that upstream's previous tool
  list, and the refresh task is restarted if it crashes. `SIGHUP` reloads
  the policy inline when the refresh task is not running.
- `.env.example` no longer enables external key verification out of the
  box. `KEYSTONE_MCP_AUTH_SERVICE_URL` set without
  `KEYSTONE_MCP_AUTH_SERVICE_TOKEN` is now refused at startup instead of
  silently locking every api-key login out.
- Proxied tools that answer with plain text, several content blocks, images
  or resources reach the client unchanged instead of failing with a JSON
  decode error.
- Access tokens issued by refresh keep their RFC 8707 resource binding;
  previously they were unbound, and
  `KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR=true` rejected them.
- `handle_google_callback` normalizes the verified Google email the same
  way token sign-in does (lower-cased, trimmed) before using it for the
  domain check, the directory lookup, and the subject/claims written into
  the issued token — defensively, in case the upstream Google OIDC client's
  own normalization is ever relaxed.
- `POST /register` with `redirect_uris: null` no longer raises an
  unhandled `TypeError` and a 500 when
  `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` is set; it is refused the
  same way an empty `redirect_uris` list is (`invalid_redirect_uri`).
- `RouterRegistry.add_route` is now atomic: it publishes to FastMCP
  *before* writing to the route registry, instead of after. Previously,
  re-publishing an already-live tool under a schema that cannot become a
  handler signature (a parameter named `from`, or `max-results`, which is
  not a legal Python identifier) left a "ghost tool" behind — the registry
  entry was removed by the error handler, but the old tool stayed
  published in FastMCP with no registry entry pointing at it, and could
  never be found again to remove. Now a failed publish (new or update)
  leaves the registry and FastMCP exactly as they were: the previous
  version, if any, stays fully published in both places. The background
  refresh no longer caches a fingerprint for a route that was skipped this
  way (or refused by the published-name collision check), so it is retried
  on the next tick instead of being silently treated as already up to
  date; a skipped tool that had a working previous version keeps its old
  fingerprint, so it is still correctly removed once the upstream really
  does stop offering it. An RBAC allow pattern that names exactly such a
  skipped tool is logged as "not verified" (like an unavailable-namespace
  pattern) instead of refusing startup; see "Unpublishable tools" in
  [`docs/rbac-policy-format.md`](docs/rbac-policy-format.md#4-validation-rules).
- `SurfaceReconciler`'s background loop cleared the SIGHUP policy-reload
  event before running the tick that was supposed to read it, so
  `force_policy` was always `False`: a SIGHUP (or
  `request_policy_reload()`) while the policy file itself was unchanged
  never actually forced a reload. The event is now read by the tick before
  it is cleared.
- With `KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=0`, the startup WARNING for
  an unreachable upstream no longer claims it is "retried on every refresh
  tick" — there is no background refresh task in that mode, so it now says
  the upstream "will not be retried; refresh is disabled" instead.
- A `.env`/`KEYSTONE_MCP_ENV_FILE` line with no `=` no longer puts the raw
  line's text into the `ConfigError` it raises, which could otherwise leak
  a secret (for example a continuation line of a multi-line PEM block in a
  shared file) into a log or traceback. Only a line starting with
  `KEYSTONE_MCP_` is refused this way; any other line with no `=` is
  instead skipped with a warning naming just the file and line number.
- `keystone-mcp users import` no longer aborts the whole batch with exit
  code 3 ("database is unavailable") when a single source record has an
  invalid email, an over-255-character `full_name`, or a malformed role
  name (previously a database error on PostgreSQL; SQLite did not even
  enforce the column length, so the same bad record behaved differently
  per backend). Such records are now validated before being written,
  skipped individually with their reason printed (no source payload or
  token), counted as `skipped_invalid=N` in the summary, and the rest of
  the batch is still imported with exit code `0`. The same command's
  `admin_or_block_changes` count (and its `--dry-run` warning) now also
  catches a block being *re-applied* by a re-import (source still reports a
  block that was lifted locally through `users_unblock`) and any role
  granted locally through `users_grant_role` being silently dropped because
  the source does not report it; `--help` and
  [`docs/users.md`](docs/users.md) describe both directions. It also now
  writes the same trimmed `full_name` it validated, instead of the raw,
  untrimmed source value, and checks and trims `created_by` the same way
  (capped at the column's 320 characters) instead of letting an over-length
  value reach the database and abort the whole batch.
- `keystone-mcp users grant-admin`/`users import` print the resolved
  absolute path of a SQLite `KEYSTONE_MCP_USERS_DB_URL` (instead of the
  configured relative one) in the `Users directory: …` line, and warn
  before creating a brand-new, empty database file; `grant-admin`
  additionally refuses to run against a database that does not exist yet
  unless `--create` is passed, leading with a single consistent "no users
  database at …" message instead of two contradictory ones. Running
  `grant-admin` from a directory other than the server's working directory
  against the default relative path previously created (and wrote the new
  administrator into) an unrelated, empty database silently.
- `docs/security-model.md` explains access as three separate settings
  (users directory, sign-in secret, policy file) and the local and
  production profiles; `docs/production-checklist.md` is aligned with the
  same rules.
- A denied call (`UnauthorizedError`, no verified identity) on a proxied
  upstream tool now raises `ToolError` instead of returning an ad hoc
  `{"state": "error", "code": "unauthorized", ...}` dict. A route published
  in transparent mode carries the upstream's own `outputSchema`, and a
  strict client validates `structuredContent` against it — that dict did
  not match it, so the denial previously surfaced as a confusing schema
  validation error instead of a plain tool-call failure.
- `examples/production/upstreams.yaml`'s header comment no longer claims
  `KEYSTONE_MCP_UPSTREAMS_PATH` is "already" pointed at it by `.env` — the
  shipped `.env.example` ships that line commented out, so the comment now
  tells the operator to set it (pointing at the explicit step in
  `docs/paths/production-docker.md`) instead of implying it needs nothing.

## [0.3.1] - 2026-10-10

### Added

- Structured logging: `KEYSTONE_MCP_LOG_*`, NDJSON/text formatters, HTTP access
  middleware (no query or credentials), `request_id` correlation, default secret
  redaction, uvicorn access log disabled. Operator guide
  [`docs/observability-logging.md`](docs/observability-logging.md) and Vector
  reference [`docs/examples/vector-keystone.toml`](docs/examples/vector-keystone.toml).

### Changed

- README **Observability** section: metrics and logging documented as
  production-ready (contract in-repo; collectors on the deployment side).
- Observability guides cross-link and clarify scope (metrics/audit vs app logs).

## [0.3.0] - 2026-10-10

### Added

- **Prometheus tool-call observability** — `keystone_mcp_tool_call_attempts_total`,
  `keystone_mcp_tool_invocations_total`, and `keystone_mcp_tool_invocation_seconds`
  with labels for tool, namespace, `auth_method`, and `oauth_client_id`; RBAC
  decision metrics include `operation` (`list_tools` / `call_tool`). See
  [`docs/observability-rbac.md`](docs/observability-rbac.md).
- Example Prometheus sidecar under `prometheus/example/` for host-installed MCP.
- `GET /healthz` for load balancer and deploy smoke checks.
- File-based upstream registry (`KEYSTONE_MCP_UPSTREAMS_PATH`) with URL validation
  and `keystone-mcp upstream validate`.
- RBAC catalog CLI: `keystone-mcp catalog validate|diff|export` (see
  [`docs/rbac-catalog-registry.md`](docs/rbac-catalog-registry.md)).
- Login and dynamic client registration rate limits (`KEYSTONE_MCP_LOGIN_THROTTLE_*`).
- GitHub OSS hygiene: Dependabot, issue/PR templates, `CODEOWNERS`.

### Changed

- Built-in `users_*` admin tools are published only when `KEYSTONE_MCP_RBAC_MODE=enforce`.
- Upstream MCP proxy HTTP client disables redirect following (`follow_redirects=false`).
- Generic deploy and observability docs (no environment-specific hostnames in the repo).

### Security

- Startup refuses `KEYSTONE_MCP_DEV_TOKENS` with `KEYSTONE_MCP_RBAC_MODE=enforce`
  unless auth-service introspection is configured.
- Upstream registry URL policy: HTTPS by default, optional dev flags for HTTP and
  private networks; rejects unsafe schemes and userinfo in URLs.
- `/metrics` and `/internal/*` remain gated by `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`.

### Fixed

- Flaky Streamable HTTP MCP client tests: injection-based upstream e2e and CI
  retries for intermittent transport errors.

## [0.2.0]

### Licensing

- Licensed under the Apache License 2.0.

### Migration

RBAC moved from a hardcoded, customer-specific role/tool catalog to a
policy-file-driven engine (`KEYSTONE_MCP_RBAC_POLICY_PATH`, format documented
in [`docs/rbac-policy-format.md`](docs/rbac-policy-format.md)). A deployment
that previously relied on the built-in customer catalog must now supply its
own RBAC policy file and, optionally, a catalog snapshot file
(`KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT`) declaring active/reserved/work-in-progress
tool names. `KEYSTONE_MCP_RBAC_ENABLED` still works but is deprecated in favor
of `KEYSTONE_MCP_RBAC_MODE` (`off` / `observe` / `enforce`).

### Added

- `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS` — per-published-tool timeout overrides
  for proxied upstream calls.
- `KEYSTONE_MCP_LOGIN_DEFAULT_LANG` — configurable login-page fallback
  language.
- `KEYSTONE_MCP_PROXY_SCHEMA_PATCHES` — deployment-supplied JSON file patching
  properties onto a proxied tool's `inputSchema`.
- `KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT` — optional catalog snapshot used to
  validate RBAC policy allow patterns against tool names the router may not
  have discovered yet.
- `KEYSTONE_MCP_REFRESH_TOKEN_TTL` — explicit, configurable refresh-token idle
  lifetime.
- `KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR` — optional strict RFC 8707
  resource-indicator enforcement.
- `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS` and
  `KEYSTONE_MCP_INTERNAL_ENDPOINTS_ENABLED` — source-address gating for the
  unauthenticated `/metrics` and `/internal/*` endpoints.

### Removed

- The hardcoded, customer-specific tool catalog, the legacy `KEYSTONE_MCP_ANALYTICS_*`
  single-upstream configuration and the two per-tool timeout variables named after
  specific tools (replaced by `KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS`). Upstreams are
  configured exclusively through `KEYSTONE_MCP_UPSTREAMS`.

### Deprecated

- `KEYSTONE_MCP_RBAC_ENABLED` — use `KEYSTONE_MCP_RBAC_MODE` instead. Setting
  it now logs a startup deprecation warning.

### Changed

- `setup.sh` records credentials for an existing Redis and starts a local
  Redis container only when that option is chosen and port 6379 is free.
- Default value of the webhook `KEYSTONE_MCP_WEBHOOK_CLIENT` /
  `KEYSTONE_MCP_WEBHOOK_PROJECT` is now empty (previously a customer-specific
  default); routes that use the reference webhook adapter must name both
  explicitly.
- Default login language is `en` (previously implicit/browser-dependent).

### Security

- The per-identity throttle is now enforced exactly once per tool call in
  every RBAC mode (previously it could be bypassed or double-counted
  depending on mode).
- `/metrics` and `/internal/*` are gated by
  `KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS` (source-address allowlist) instead of
  trusting the absence of a client-supplied header.
- Startup now refuses to run with RBAC audit enabled and no
  `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT` set, instead of emitting guessable
  pseudonymized subject identifiers.
- Refresh tokens carry a real, bounded idle lifetime
  (`KEYSTONE_MCP_REFRESH_TOKEN_TTL`) instead of an unbounded one.
- The `external_http` reference adapter no longer lets a client-supplied
  header override the verified identity header.
- Resource-indicator (RFC 8707) audience comparison is normalized
  (case, default port, trailing slash), and strict enforcement is available
  via `KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR`.
- The login-pending store requires Redis; it no longer falls back to an
  in-memory store outside of tests.

### Fixed

- `users_unblock` now sends the verified actor header to the users directory,
  matching every other `users_*` mutation.
- The per-tool upstream timeout override is actually applied to the proxying
  HTTP client, not just recorded.
- A failed downstream HTTP call from an adapter now returns the standard
  error envelope (`{"state": "error", ...}`) instead of surfacing as an
  opaque internal tool error.

## [0.1.0]

Initial internal release: OAuth 2.1 authorization server and resource
server, configurable router with adapters, deterministic `task_id`, identity
propagation, and the first hardcoded tool catalog.
