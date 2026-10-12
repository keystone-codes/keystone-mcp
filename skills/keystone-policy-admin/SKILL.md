---
name: keystone-policy-admin
description: Change which Keystone-MCP roles may call which tools — read the policy and the tool catalog, create or change a role, add or remove allow patterns, set deny / critical / human-only lists, roll back. Use when asked to give a role access to a service's tools, to restrict a tool, or after a new service appears behind Keystone-MCP.
---

# Keystone-MCP policy administration

The Keystone-MCP connector exposes nine `policy_*` tools backed by the RBAC
policy file on disk. Pick the tool from the table below and call it once with
exactly the listed arguments. Do not probe other tools and do not guess tool
names or patterns.

Only human administrators can call mutation tools. Changes take effect
immediately on this server — no restart is needed.

## What the policy is

Roles are named sets of glob patterns over published tool names
(`<namespace>_<tool>` from the live catalog). A person's effective access is
the union of every role they hold. `deny` overrides any allow, including
`administrator`. `default_deny` is always on. Every change is validated
against the live catalog before it is written.

## Request to tool

| Request | Tool | Arguments |
| --- | --- | --- |
| Show the policy | `policy_read` | `{}` |
| What tools does service X have | `policy_catalog` | `{"namespace": "files"}` |
| Who can call tool Y / what can role R call | `policy_catalog` | `{"role": "viewer"}` |
| Check before changing | `policy_validate` | `{"policy": {...}}` optional |
| Create or replace role R with tools | `policy_role_set` | `{"role": "R", "allow": ["..."], "expected_hash": "..."}` |
| Give role R access to service X | `policy_allow_add` | `{"role": "R", "patterns": ["files_*"], "expected_hash": "..."}` |
| Take patterns away from R | `policy_allow_remove` | `{"role": "R", "patterns": ["..."], "expected_hash": "..."}` |
| Forbid tool T for everyone | `policy_list_set` | `{"list": "deny", "patterns": [...], "expected_hash": "..."}` |
| Make T require a human | `policy_list_set` | `{"list": "requires_human_identity", "patterns": [...], "expected_hash": "..."}` |
| Make T critical (no allow cache) | `policy_list_set` | `{"list": "critical_tools", "patterns": [...], "expected_hash": "..."}` |
| Delete role | `policy_role_delete` | `{"role": "R", "expected_hash": "..."}` |
| Undo the last change | `policy_rollback` | `{}` |

## Rules

1. **Always `policy_read` first** and pass `content_hash` as `expected_hash` on
   every mutation. If the file changed underneath you, retry once after a fresh
   read.
2. **Never invent tool names.** Take patterns from `policy_catalog`. To grant a
   whole service, use `<namespace>_*`.
3. **`policy_role_set` replaces the whole role** — description and allow list.
   To add patterns, use `policy_allow_add`.
4. **`policy_list_set` replaces the whole list** — read the current list from
   `policy_read`, merge your edit, and send the full new list.
5. **`deny` applies to everyone**, including `administrator`.
6. **`*` on a role means every tool**, including services added later.
7. **A role still assigned to people cannot be deleted** — reassign with
   `users_set_roles` / `users_revoke_role` first (`keystone-user-admin` skill).
8. **Never remove the last path to policy tools** or lock out every role; the
   server refuses (`self_lockout_forbidden`, `policy_invariant`).
9. **`policy_rollback` undoes exactly one write** and runs the same checks as a
   normal mutation.
10. **`version` in the file is not touched** by the tools. If the operator
    tracks versions manually, they edit the field themselves.

## Confirm first

Ask the user to confirm before: `policy_role_delete`; any `policy_allow_remove`
or `policy_role_set` that narrows access; `policy_list_set` on `deny` or
`critical_tools`; `policy_rollback`. State which roles and patterns change,
then act.

## Reading the result

Success is `{"state": "done", ...}` with `changed` (bool), `content_hash`
(64-char hex), and often `warnings` (list of strings). Mutations may also
return `role`, `added`, `removed`, `list`, or `patterns`.

`policy_read` adds `writable`, `mode`, `unreachable_tools`, `unverified_patterns`,
and `backup_available`. A warning `unverified` means an upstream namespace is
down — the pattern is accepted and checked when that service appears.
`unreachable_tools` lists published names no role may call.

Failure is `{"state": "error", "code": "...", "message": "..."}`.

## Errors

| Code | Meaning | Action |
| --- | --- | --- |
| `unmatched_pattern` | Pattern does not match any published tool | Show `policy_catalog`; ask which name to use |
| `policy_conflict` | `expected_hash` stale | `policy_read` once, retry the mutation once |
| `policy_readonly` | File or instance is read-only | Tell the operator; see `docs/policy-admin.md` |
| `role_in_use` | Role still on accounts | Reassign roles via `keystone-user-admin`, then retry |
| `self_lockout_forbidden` | Would remove your own policy access | Refuse; another administrator must do it |
| `policy_invariant` | Would leave no administering role | Refuse; explain |
| `forbidden` | Service account called a mutation | Stop; a human must change policy |
| `validation_error` | Bad argument or empty pattern list | Fix arguments |
| `role_not_found` | Unknown role on remove/delete | `policy_read` and correct the name |
| `policy_invalid` | YAML or contract broken | Do not retry blindly; show the message |
| `nothing_to_rollback` | No `.bak` backup | Explain; restore from ops backup if any |
| `service_unavailable` | Directory unreachable for invariant check | Report; retry later |

**Never retry a failed mutation blindly.** After `policy_conflict`, read once
and retry once. For other errors, read current state with `policy_read` first.

## After a new service is installed

A service catalog package may supply recommended policy rows (`recommended_policy`:
`{role, allow}` entries) as text from the operator or from an installer skill.
Show **which roles and patterns** would be added. Apply only after confirmation,
one `policy_role_set` or `policy_allow_add` call per role.

## Examples

**Give the viewer role read access to the files service** — catalog, then add:

```
policy_catalog {"namespace": "files"}
policy_read {}
policy_allow_add {"role": "viewer", "patterns": ["files_*"], "expected_hash": "<hash>"}
```

**New service `docai` appeared** — new role from recommended lines:

```
policy_read {}
policy_role_set {"role": "docai_user", "allow": ["docai_*"], "expected_hash": "<hash>"}
```

**Forbid `files_get_download_link` for everyone** — merge into deny list:

```
policy_read {}
policy_list_set {"list": "deny", "patterns": ["<existing deny entries>", "files_get_download_link"], "expected_hash": "<hash>"}
```

**Undo the last change**:

```
policy_rollback {}
```
