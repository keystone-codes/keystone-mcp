# Policy administration from the agent

Keystone-MCP can change its own RBAC policy file through nine built-in
`policy_*` tools (`policy_read`, `policy_catalog`, `policy_validate`, and
six mutation tools). They let a human administrator adjust roles, allow
patterns, and global deny / critical / human-only lists without editing YAML
by hand. The agent workflow is the
[`keystone-policy-admin`](../skills/keystone-policy-admin/SKILL.md) skill;
this page is for whoever runs the server.

## Enable mutation tools

1. Set `KEYSTONE_MCP_RBAC_MODE=enforce` (or `observe` for dry runs without
   enforcement).
2. Set `KEYSTONE_MCP_POLICY_TOOLS` to `full` on the instance that may write
   the file (`read-only` allows `policy_read` / `policy_catalog` /
   `policy_validate` only; `off` hides the whole namespace).
3. Mount the policy file **and its parent directory** read-write at
   `KEYSTONE_MCP_RBAC_POLICY_PATH`. Atomic writes rename a temp file next to
   the target; a read-only mount or a ConfigMap subpath cannot work.
4. Keep a backup: each successful mutation rotates the previous file to
   `<policy-path>.bak` (one generation).

See [rbac-policy-format.md](rbac-policy-format.md) for file layout.

## What happens on each change

1. The candidate document is validated like a hot-reload (catalog match,
   invariants, self-lockout checks).
2. Only one mutation runs at a time in a process (`asyncio` lock) and, on
   platforms with `flock`, across processes on the same volume (lock file
   `<policy-path>.lock` — do not delete it while the server runs; the policy
   directory must be writable, same as for `.bak`). If another writer holds
   the lock until the timeout, the call returns `policy_conflict`.
3. The previous bytes are copied to `.bak` with the same permissions as the
   live file (`copy2` via a unique temp file), then the new YAML is written
   atomically as `.<policy-name>.*.tmp` in the policy directory; the
   directory is `fsync`ed after replace when the OS allows it.
4. The in-process policy manager reloads from disk; connected clients may
   receive `notifications/tools/list_changed` on the next refresh boundary.
5. An audit event `rbac_policy_mutation` is emitted (actor, operation,
   outcome — not allow patterns or email).
6. Metrics record the mutation outcome on the `policy_*` tool series.

Hand-written **comments in the policy file are not preserved** on tool writes
(PyYAML round-trip). Keep explanatory text in a `README` next to the file, in
role `description` fields, or in your runbook.

## Several replicas

- **Agent-driven changes (`policy_*`):** a successful write bumps a revision
  marker in Redis (`KEYSTONE_MCP_POLICY_REDIS_REVISION_KEY`, default
  `km:rbac:policy:revision`). Every other replica reloads its **local** policy
  file on the next MCP call (at most about one second later). On a **shared
  volume** that is enough — all replicas read the same bytes after the writer
  commits.
- **No shared volume:** replicas can enforce different files. That shows up as
  `keystone_mcp_rbac_policy_in_sync 0`, in trusted `/readyz` details as
  `policy_in_sync: false`, and once per revision in the log. To realign: copy
  the policy file to every replica and send `SIGHUP` to each process.
- **Operational layout:** keep `KEYSTONE_MCP_POLICY_TOOLS=full` on one replica
  (writable mount) and `read-only` (or `off`) on the others so administrators
  do not hit silent `policy_readonly` on random pods.
- **Shared volume (manual edits):** without `policy_*`, new bytes still appear
  on the refresh timer (`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`) or on
  `SIGHUP` when the content hash changes. The file lock next to the policy
  coordinates writers when the filesystem supports `flock`. On NFS, locking
  only helps when the NFS server honours `flock`.
- **Windows:** file locking is in-process only; use a single writer replica.

Example Prometheus alert when replicas diverge:

```yaml
- alert: KeystonePolicyReplicasDiverged
  expr: min(keystone_mcp_rbac_policy_in_sync) == 0 or count(count by (content_hash) (keystone_mcp_rbac_policy_info)) > 1
  for: 5m
  annotations:
    summary: "Keystone replicas enforce different RBAC policy files"
```

## Kubernetes

The example ConfigMap mounts policy as read-only data. Do not make that
file writable with `subPath` tricks or an init container. For agent-driven
changes, store policy on a PVC (writable mount of the directory) or set
`KEYSTONE_MCP_POLICY_TOOLS=read-only` and edit policy out of band. See
[paths/kubernetes.md](paths/kubernetes.md).

## Manual rollback

On the host (or inside the container):

```bash
mv /path/to/rbac-policy.yaml.bak /path/to/rbac-policy.yaml
kill -HUP <keystone-mcp-pid>
```

Or call `policy_rollback {"expected_hash": "<file_hash from policy_read>"}`
from the agent when `.bak` exists and the file is writable. Rollback runs the
same validation as other mutations, including `role_in_use` when a role would
disappear.

## Production recommendations

- Put sensitive tools in `requires_human_identity`, including the mutating
  `policy_*` tools, so service accounts cannot change policy.
- Service accounts already receive `forbidden` on mutations; keep API keys
  scoped to automation roles without `policy_*` access.
- Review `rbac_policy_mutation` audit entries after changes; they intentionally
  omit pattern lists and personal data.

## systemd / host install

The policy file should be owned by the `keystone-mcp` service user and
writable by that user. Place `rbac-policy.yaml` in a directory the service
can rename within (for example `/opt/keystone-mcp/policy/`). The `.bak` file
lives beside it. See [deploy.md](deploy.md).
