# RBAC policy file format (v2)

Normative specification of the keystone-mcp RBAC policy file, the optional
catalog snapshot file, and the environment variables that select them. This
document is the contract a downstream deployment repository implements when it
ships its own policy as an overlay. The file can also be changed through the
`policy_*` tools — see [policy-admin.md](policy-admin.md).

The platform hardcodes no role name and no tool name, with one exception named
in [Core critical built-ins](#core-critical-built-ins).

- Loader and contract: `src/keystone_mcp/rbac/policy.py`
- Startup gate and hot-reload: `src/keystone_mcp/rbac/loader.py`
- Catalog snapshot: `src/keystone_mcp/rbac/catalog_snapshot.py`
- Enforcement: `src/keystone_mcp/router/rbac_middleware.py`
- Worked example: `examples/rbac-policy.full-example.yaml`
- Shipped default: `config/rbac-policy.yaml`

## 1. Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `KEYSTONE_MCP_RBAC_MODE` | no (default `off`) | `off` — no RBAC middleware, no policy loaded. `observe` — decisions evaluated and audited, never enforced. `enforce` — decisions enforced (catalog filtered, calls denied). |
| `KEYSTONE_MCP_RBAC_POLICY_PATH` | yes when mode is `observe` or `enforce` | Absolute or relative path to the policy YAML. Must exist and be a file at startup, else `ConfigError`. |
| `KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT` | no (default empty) | Path to a catalog snapshot YAML. Empty means no snapshot: every tier is empty. When set, the file must exist, else `ConfigError`. |

`observe` and `enforce` additionally require `KEYSTONE_MCP_REDIS_URL` (the
shared cache-revision marker) and a users directory (built in by default,
see [users.md](users.md)).

## 2. Policy file

```yaml
version: "2.0.0"
default_deny: true
roles:
  <role-name>:
    description: "..."           # optional
    allow: ["<glob>", ...]       # required, non-empty
deny: ["<glob>", ...]                       # optional
requires_human_identity: ["<glob>", ...]    # optional
critical_tools: ["<glob>", ...]             # optional
reserved_allow_patterns: ["<glob>", ...]    # optional
tool_dispositions:                          # optional
  <label>: ["<glob>", ...]
```

Every section other than `version`, `default_deny` and `roles` is optional; an
absent section is an empty list. Any other top-level key is a
`PolicyContractError` naming the offending keys — including keys from an older
hand-rolled format, so a v1 file fails loudly rather than silently losing a
section.

### 2.1 Patterns

A pattern is an `fnmatch` glob (`*`, `?`, `[seq]`) matched against the
**client-visible published tool name** — the name the MCP client sees, namespace
prefix included (`Route.published_name`, e.g. `reports_read` for a route named
`read` mounted under namespace `reports`). The bare pattern `*` matches
everything.

The glob is matched against the full published name, so `billing_*` covers
**every** tool of namespace `billing`, including `billing_admin_report` if that
upstream happens to have a tool named `admin_report`. To give a role less than
all of `billing`, list the tool names explicitly, add a `deny` pattern, or move
the administrative tools into a separate registry entry with their own
namespace (not starting with `billing_`) using `include_prefixes`/
`strip_prefix`.

Allow patterns match tools, prompts and resources by their published name
(`<namespace>_<name>` for tools, prompts, static resources and resource
templates — see [facade.md](facade.md)). Example: upstream resource
`handbook` in namespace `hello` is allowed with `hello_handbook`, not by URI.

### 2.2 `version`

Free-form non-empty string. Emitted in every audit event as `policy_version`
and logged with the file's SHA-256 (`policy_content_hash`) whenever a policy
becomes active. Change it on every policy change so audit records are
attributable; the platform does not parse or compare it.

### 2.3 `default_deny`

Must be the boolean `true`. `false` is refused
(`default_deny must be true (deny-by-default)`); a non-boolean, including the
string `"false"`, is refused at parse time. A tool that no allow pattern of any
assigned role matches is denied.

### 2.4 `roles`

A mapping of role name to role body. The users directory accepts only role
names declared in this file; assigning a person a role that is not in `roles`
fails with `validation_error` and the message `unknown role: <name>` (see
[users.md](users.md)). At least one role must be declared. Each role body:

- `allow`: required, a non-empty list of patterns. An empty or whitespace-only
  pattern is refused.
- `description`: optional free text. Not interpreted.

Duplicate role names are refused. There is no privileged role: nothing in the
platform treats a role called `administrator` differently from one called
`root`, `owner` or `viewer` when evaluating a policy decision.

The users directory itself reserves one name, `administrator`: it refuses to
block or demote the last active administrator, refuses an administrator
removing their own `administrator` role, and seeds the first administrator
from `KEYSTONE_MCP_SUPERADMIN_EMAIL`. These are directory-level safeguards,
not a policy rule — policy evaluation still treats `administrator` like any
other role.

**Multi-role semantics.** A user's effective permission set is the *union* of
the allow patterns of all roles assigned to them. A user with no roles is
denied everything.

Why: [ADR 0002](adr/0002-roles-in-the-policy-file.md).

### 2.5 `deny`

Global kill list. A tool matching any `deny` pattern is denied for every role,
including a role whose `allow` is `*`. Applied before allow evaluation.

### 2.6 `requires_human_identity`

Tools that additionally require an interactive human login. A call that the
role union permits is still denied with reason `human_identity_required`
unless the verified token carries `interactive: true` — a claim every
interactive sign-in provider sets (Google and any configured OIDC provider;
see `login-providers.md`), never a machine's api_key sign-in
(`has_interactive_human_identity` in
`src/keystone_mcp/rbac/human_identity.py`). Use it for irreversible
confirming operations that must never run under a machine token. Service
accounts never satisfy `requires_human_identity`.

Tools listed here are omitted from `tools/list` for callers who did not sign in
interactively (for example a DEV token or an API key sets `interactive: false`).
A production example lists `users_*`, `service_accounts_*`, `api_keys_*`, and
`policy_*` with a comment that administrators who sign in non-interactively are
refused those tools unless an entry is removed.

### 2.7 `critical_tools`

Tools whose role resolution must be synchronous: the user-directory allow cache
is bypassed, so a role revoked seconds ago takes effect on the next call. Costs
one directory round trip per invocation.

#### Core critical built-ins

The following are **always** critical, whatever the policy says, because the
core catalog (`src/keystone_mcp/catalog/builtin.py`) registers them as a
platform primitive: `users_*` and `policy_*`, published only when
`KEYSTONE_MCP_RBAC_MODE=enforce`. They are critical whenever they are published, and
need not be repeated in `critical_tools`; listing them is harmless.

### 2.8 `reserved_allow_patterns`

Allow globs that are permitted to match *only* reserved or WIP names from the
catalog snapshot. Every other allow pattern must match at least one name in
`active | reserved | wip`, or startup is refused as a typo (see §4). Use this
for a family of tools named in policy before any member of it exists.

### 2.9 `tool_dispositions`

Documentation only; never consulted by enforcement. A mapping of label to
patterns, used by `scripts/generate_role_matrix.py` to fill the `Disp.` column
of the generated matrix. Labels are free-form (`R`, `W`, `D`, `P`, … are
conventions, not a schema). Entries are evaluated **in file order** and the
first matching label wins; a tool matching nothing is labelled `W`
(`FALLBACK_DISPOSITION`).

### 2.10 Management roles and full administrators

A **management role** is any declared role that reaches at least one
*mutating* built-in administration tool (`users_*`, `service_accounts_*`,
`api_keys_*`, `policy_*`, excluding read-only tools such as `users_list`,
`policy_read`, `policy_catalog`, and `policy_validate`). A role that only
grants read-only administration tools is not a management role, but
`users_list` exposes every person's email and roles and `api_keys_list`
exposes key labels and expiry — grant those read tools deliberately.

A **full administrator** is a person whose combined roles reach every
built-in administration tool name except those blocked by the policy-wide
`deny` list. The role name does not matter; `owner: ["*"]` and
`administrator: ["*"]` are equivalent when both reach the full tool set.

**Rule:** only a full administrator may perform a change after which someone
would gain or lose a management role, or change any account that already
holds a management role (including granting or revoking an ordinary role on
such a person). The same rule applies to `policy_*` changes that touch
administration (see [policy-admin.md](policy-admin.md#who-can-change-what)).
Delegated roles such as `hr: ["users_*"]` may still create, block, or update
people who hold only non-management roles.

**Delegation:** a person who is not a full administrator may grant (through
`users_*` and `service_accounts_*`) only roles whose permissions they already
have. Comparison uses published tool names from the live catalog plus the
catalog snapshot (`active`, `reserved`, `wip`). For allow patterns that do not
match any published name (for example a glob for a service that is not live
yet), the grant is allowed only when the actor's roles include the same
pattern literally (or `*`). Removing roles is not limited. Example:
`hr: ["users_*", "docs_read"]` may grant `reader: ["docs_read"]` but not
`finance: ["finance_*"]`.

Use patterns that cover whole administration families (`api_keys_*`, not a
hand-picked subset of key tools) so a full administrator is recognized
reliably. Management checks use the stricter of the in-memory policy snapshot
and the policy file on disk when they differ.

## 3. Catalog snapshot file

```yaml
active: ["<tool>", ...]     # published and known live in the reference deployment
reserved: ["<tool>", ...]   # named in policy before publication; never matched live
wip: ["<tool>", ...]        # work in progress
```

All three sections are optional and hold exact tool names, not globs. Unknown
keys, a non-mapping root, or a non-string entry raise `CatalogSnapshotError`.
An empty or absent file yields the empty snapshot.

How each tier is used:

- `active` is merged with the discovered live catalog for reachability checks,
  so a deployment that mounts only part of the catalog still loads the full policy.
- `reserved` counts as a known name for reachability but is never a live call.
- `wip` satisfies only patterns listed in `reserved_allow_patterns` (and
  contributes to the general reachability universe).

Worked example: `examples/catalog-snapshot.example.yaml`.

Offline validation without starting the server:
[rbac-catalog-registry.md](rbac-catalog-registry.md) (`keystone-mcp catalog validate`).

## 4. Validation rules

Structural (`validate_policy_structure`, applied on every load):

1. `default_deny` is `true`.
2. `version` is a non-empty string.
3. At least one role is declared; role names are non-empty and unique.
4. Every role has a non-empty `allow` list with no empty patterns.
5. No unknown top-level keys; `deny`, `requires_human_identity`,
   `critical_tools`, `reserved_allow_patterns` are lists when present, and
   `tool_dispositions` is a mapping when present.

Catalog gate (`assert_live_catalog_validation`, applied at startup and on every
hot-reload against the live route table plus the snapshot):

6. **Every allow pattern must be reachable.** A pattern matching nothing in
   `live | snapshot.active | snapshot.reserved | snapshot.wip` refuses startup
   with `unmatched allow patterns (typo or missing catalog/WIP entry): …`. A
   pattern listed in `reserved_allow_patterns` must match something in
   `snapshot.reserved | snapshot.wip`. The bare `*` is satisfied by a non-empty
   catalog.
7. **Unreachable tools are a warning, not a refusal.** Live tools that no role
   can reach (and that are not in `deny`) are logged at WARNING as
   `rbac policy leaves N tool(s) unreachable by any role: …`. Startup
   continues: publishing a tool nobody may call is a deployment choice.

**Unavailable upstreams.** An unmatched allow pattern is not always a typo: it
may simply belong to an upstream namespace that has not answered a discovery
or refresh call yet. Two reclassifications turn what would otherwise be a
refusal into a WARNING instead:

- An allow pattern's *head* is the part before its first glob metacharacter
  (`*`, `?`, `[`) — the whole pattern when it has none. A pattern's *owner* is
  the longest registered upstream namespace `N` such that the head starts
  with `N + "_"` (longest so that, with both `billing` and `billing_admin`
  registered, `billing_admin_*` belongs to `billing_admin`, not `billing`). A
  pattern that does not start with `<namespace>_` has no owner — for example
  `doc*` or a pattern whose glob starts at position 0, like `*_search` —
  and stays a hard error regardless of upstream availability. **A pattern
  meant for one upstream must therefore start with `<namespace>_`.**
- An unmatched pattern is logged as `rbac allow patterns not verified:
  upstream namespace <namespace> is unavailable: <role>:<pattern>, …; they are
  checked when it comes up` — one line per namespace — instead of refusing,
  when it has an owner and that namespace is currently unavailable (its last
  discovery or refresh attempt failed, including "never discovered yet"). A
  pattern listed in `reserved_allow_patterns` is never reclassified this way:
  it is checked against the catalog snapshot only, independent of upstream
  availability. Once the namespace's next refresh succeeds, the usual
  background drift check (`log_live_catalog_drift`) re-validates it against
  the live catalog; a genuine typo then surfaces as an ERROR
  (`rbac policy has unmatched allow patterns after catalog change: …`) without
  taking the policy down — the background check never refuses, only logs.
- The bare `*` pattern can only be unmatched when the whole pattern catalog
  (`live | snapshot.active | snapshot.reserved | snapshot.wip`) is empty. That
  is logged as `policy pattern * matched no tools: catalog is empty: …` and
  never refuses startup either, independent of upstream state — this also
  covers a deployment with no upstreams and no built-in tools enabled (for
  example `KEYSTONE_MCP_RBAC_MODE=observe` with none configured), and
  `keystone-mcp catalog validate` run against an empty live catalog.

A disabled upstream (`enabled: false` in the registry) is never registered, so
it has no namespace to be "unavailable" — a pattern meant for it is a hard
error, same as any other pattern with no owner.

**Unpublishable tools.** A namespace can be fully *available* (its own
discovery or refresh succeeded) while one of its tools still cannot be
turned into a published MCP tool. Since proxied tools are published with the
upstream's own `inputSchema` verbatim (no Python function signature is built
from it — see [`docs/facade.md`](facade.md)), a parameter name that is not a
legal Python identifier (`max-results`) or is a reserved keyword (`from`) no
longer makes a tool unpublishable; what remains in this category is a schema
FastMCP's own tool model otherwise refuses (for example a malformed
`annotations` patch). That one tool is skipped (logged at ERROR, `upstream tool skipped namespace=…
tool=…: …`) without dropping the rest of the namespace. An allow pattern
that glob-matches exactly that tool's published
name is logged the same way as an unavailable-namespace pattern — `rbac
allow patterns not verified: upstream namespace <namespace> has a tool that
could not be published: <role>:<pattern>, …; they are checked once it
publishes` — instead of refusing. It is re-checked on every subsequent
refresh tick (the tool's own registration is retried every tick too, so a
later schema fix on the upstream side publishes it and clears both the
WARNING and the ERROR), and the marker is dropped once the upstream stops
offering the tool at all. A pattern listed in `reserved_allow_patterns` is
never reclassified this way either.

Additionally, with `KEYSTONE_MCP_RBAC_MODE` in `observe`/`enforce`, startup is
refused when upstream discovery failed entirely — every configured upstream
unavailable — because an empty live catalog would validate a policy against
nothing. `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true` refuses startup on *any*
unavailable upstream, regardless of RBAC mode (see
[`docs/environment.md`](environment.md)).

Everything else is enforced at request time, not at load time: a tool absent
from the catalog is simply denied by `default_deny`.

## 5. Hot-reload semantics

- Triggers: `SIGHUP` to the server process (`install_policy_reload_signal`), or
  a change to the policy or catalog-snapshot file bytes detected on the
  background refresh loop (`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`, default 300).
- The reload re-reads the policy file *and* the catalog snapshot file, then runs
  the full structural and catalog validation against the current live route
  table (after any upstream catalog refresh in the same tick).
- **Atomic swap.** On success the new snapshot replaces the active one under a
  lock, and the new `version`/`content_hash` is logged and reported to metrics.
  Every gate that lives in the policy — allow patterns, `deny`,
  `requires_human_identity`, `critical_tools`, `tool_dispositions` — changes
  together with it, because they are all fields of the same policy object.
- **Rollback.** Any failure (missing file, YAML error, contract violation,
  unreachable pattern, unreadable snapshot) is logged as
  `rbac policy hot-reload rejected: …`; the previously active policy keeps
  serving. A rejected reload never leaves the process without a policy.
- Startup is different: a failure there is fatal (`PolicyLoadError`).
- Requests in flight see either the old or the new policy, never a mix.

**Tool writes.** A later release's administration tools (`policy_*`) change
this same file from inside the process, through
`keystone_mcp.rbac.policy_store.PolicyStore` (gated by
`KEYSTONE_MCP_POLICY_TOOLS`, see [environment.md](environment.md)). A write is
atomic (`.tmp` in the same directory, `fsync`, `os.replace`), keeps exactly one
backup generation (`<policy>.bak`, overwritten on every write), and reloads the
new file in place through the same `RbacPolicyManager.reload` — and therefore
the same structural and live-catalog gate — a hot-reload runs. Hand-written
YAML comments are never preserved across a tool write (the writer is plain
PyYAML, not `ruamel.yaml`): the file as it looked immediately before the write
survives in `.bak`. Other replicas sharing the same file on a common volume
pick the change up on their own next background tick, exactly as they would
pick up a hand edit.

## 6. Migrating from v1

v1 kept part of the policy in Python. Every one of those constants is now a
section of the YAML file. A v1 policy file loads only after `version` is set to
`2.0.0` (any non-empty string is accepted, but the sections below must exist for
behaviour to be preserved), and any leftover unknown top-level key is refused.

| v1 Python location | v2 policy section |
|---|---|
| `rbac/policy.py: CANONICAL_ROLES` (the fixed four role names) | `roles` — role names are now whatever the file declares; the constant is deleted, and no check compares role names to a fixed set |
| `rbac/policy.py: RESERVED_ALLOW_PATTERNS` | `reserved_allow_patterns` |
| `rbac/human_identity.py: HUMAN_IDENTITY_REQUIRED_TOOLS` | `requires_human_identity` |
| `user_directory/critical.py: _CRITICAL_PREFIXES` / `_CRITICAL_EXACT` | `critical_tools` (plus the core built-ins, §2.7) |
| `rbac/matrix_doc.py: tool_disposition()` if/elif ladder | `tool_dispositions` |
| `rbac/published_catalog.py: ACTIVE_PUBLISHED_TOOL_NAMES` | `active:` in the catalog snapshot file |
| `rbac/published_catalog.py: RESERVED_TOOL_NAMES` | `reserved:` in the catalog snapshot file |
| `rbac/published_catalog.py: WIP_TOOL_NAMES` | `wip:` in the catalog snapshot file |

Removed with no YAML replacement:

- `rbac/policy.py: CatalogValidationResult.missing_roles` / `.extra_roles` —
  there is no canonical role set to be missing from or extra to.
- `rbac/policy.py: CatalogValidationResult.administrator_denied_tools` and the
  "administrator must allow every live catalog tool" refusal — generalized to
  the unreachable-tools WARNING (§4 rule 7). A deployment that wants the old
  hard failure keeps it as its own contract test asserting
  `CatalogValidationResult.unreachable_tools == frozenset()`.
- `rbac/human_identity.py: live_confirm_missing_d25()` and the startup gate that
  called it. It was a heuristic over tool names containing `confirm`/`commit`,
  asserting that a particular confirming tool could not go live without being
  listed in the human-identity set. That is a per-deployment invariant, not a
  platform one. A deployment that wants it should keep it as a contract test of
  its own policy file: for each live published name matching its confirming-op
  convention, assert `policy.requires_human_identity(name)`.
- The three route-name constants in `rbac/human_identity.py` (a namespace
  literal, an unpublished tool-name literal, and the helper that joined them
  into one published name). They encoded one deployment's route; a deployment
  that needs the joined name builds it from its own route table
  (`Route.published_name`).

Renamed API (for anything importing the loader directly):

| v1 | v2 |
|---|---|
| `CatalogValidationResult.unmatched_wip_patterns` | `.unmatched_allow_patterns` |
| `CatalogValidationResult.administrator_denied_tools` | `.unreachable_tools` |
| `human_identity.requires_human_identity(tool)` | `RbacPolicy.requires_human_identity(tool)` (module-level `requires_human_identity(tool, policy)` remains as a None-safe helper) |
| `critical.is_critical_tool(tool)` | `is_critical_tool(tool, policy_patterns)` / `CriticalToolMatcher(policy_patterns)` |
| `matrix_doc.tool_disposition(tool)` | `tool_disposition(tool, policy)` |
| `assert_live_catalog_validation(policy, live)` | `assert_live_catalog_validation(policy, live, catalog_snapshot=…)` |

## 7. Checklist for a deployment overlay

1. Ship a policy file at `KEYSTONE_MCP_RBAC_POLICY_PATH` with `version: "2.0.0"`,
   your role names, and your allow patterns.
2. Ship a catalog snapshot at `KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT` listing every
   published name you expect, so a typo in an allow pattern is caught at startup
   rather than becoming a silent deny.
3. List your irreversible confirming operations in `requires_human_identity`.
4. List anything privilege- or money-shaped in `critical_tools`.
5. Keep your normative role matrix downstream; regenerate it with
   `python scripts/generate_role_matrix.py --policy <policy> --snapshot <snapshot> --output <doc>`.
6. Keep your deployment-specific contract tests downstream: role-set assertions,
   per-namespace surface tests, the confirming-op/human-identity invariant, and
   any "every live tool must be reachable" rule.
