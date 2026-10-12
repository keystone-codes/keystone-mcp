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
2. The previous bytes are copied to `.bak`, then the new YAML is written
   atomically in the policy directory.
3. The in-process policy manager reloads from disk; connected clients may
   receive `notifications/tools/list_changed` on the next refresh boundary.
4. An audit event `rbac_policy_mutation` is emitted (actor, operation,
   outcome — not allow patterns or email).
5. Metrics record the mutation outcome on the `policy_*` tool series.

Hand-written **comments in the policy file are not preserved** on tool writes
(PyYAML round-trip). Keep explanatory text in a `README` next to the file, in
role `description` fields, or in your runbook.

## Several replicas

- **Shared volume:** every replica that mounts the same policy directory sees
  new bytes; each process reloads on its refresh timer
  (`KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS`) or on `SIGHUP` when the content
  hash changes.
- **No shared volume:** only one replica should have `KEYSTONE_MCP_POLICY_TOOLS=full`
  and a writable mount; set `read-only` (or `off`) on the others so
  administrators do not get silent `policy_readonly` failures on random pods.

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

Or call `policy_rollback {}` from the agent when `.bak` exists and the file
is writable.

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
