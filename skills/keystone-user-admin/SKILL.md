---
name: keystone-user-admin
description: Manage Keystone-MCP users and roles - add, update, block/unblock, grant, revoke or replace roles. Use when asked to give someone access, change a role, or disable a user in Keystone-MCP.
---

# Keystone-MCP user and role administration

The Keystone-MCP connector exposes nine `users_*` tools backed by the shared users
directory. Pick the tool from the table below and call it once with exactly the
listed arguments. Do not probe other tools and do not guess argument names.

Only administrators can call these tools. Changes take effect immediately — no
restart or re-login is needed on the server side.

## Roles

Role names come from the deployment's RBAC policy file
(`KEYSTONE_MCP_RBAC_POLICY_PATH`; see `docs/rbac-policy-format.md` and
`config/rbac-policy.yaml`). That file is written once, before anyone uses the
server. Do not invent a role name while adding a person. The directory and
the policy must use the same strings.

The role this skill grants for full access, including these tools, is
`administrator`. A person may hold several roles at once. Their effective
permissions are the union of each role's allow patterns.

## Request to tool

| Request | Tool | Arguments |
| --- | --- | --- |
| List users | `users_list` | `{}` |
| List blocked users | `users_list` | `{"is_blocked": true}` |
| Find users by role | `users_list` | `{"role": "administrator"}` |
| Find users by email fragment | `users_list` | `{"email_contains": "ivanov"}` |
| Add a person | `users_add` | `{"email": "...", "full_name": "...", "roles": ["administrator"]}` |
| Add one role, keep the rest | `users_grant_role` | `{"email": "...", "role": "administrator"}` |
| Remove one role, keep the rest | `users_revoke_role` | `{"email": "...", "role": "administrator"}` |
| Set the exact role set | `users_set_roles` | `{"email": "...", "roles": ["administrator"]}` |
| Change name or note | `users_update` | `{"email": "...", "full_name": "..."}` or `{"email": "...", "note": "..."}` |
| Revoke access | `users_block` | `{"email": "..."}` — also ends all OAuth sessions (`revoked_tokens` in the response) |
| End sessions only | `users_logout` | `{"email": "..."}` — revokes tokens; person can sign in again; directory entry not required |
| Restore access | `users_unblock` | `{"email": "..."}` — does not restore old sessions |

## Rules

1. **Never pass an actor, admin or acting-user argument.** The server takes the
   acting administrator from the authenticated session. Sending one is an error.
2. **`users_list` hides blocked users by default.** If a user seems missing,
   re-check with `{"is_blocked": true}` before reporting that they do not exist.
3. **`users_set_roles` replaces the whole role set.** For "add a role" or "remove
   a role" use `users_grant_role` / `users_revoke_role`, otherwise the user's
   other roles are silently dropped. Use `users_set_roles` only when the request
   names the complete final set.
4. **`users_add` requires both `email` and `full_name`.** If the full name is
   unknown, ask for it. Do not invent one and do not send an empty string.
5. **`users_update` changes only `full_name` and `note`.** It cannot change roles
   or email. At least one of the two must be present.
6. **There is no delete tool.** "Remove a user" means `users_block`. Add
   `users_revoke_role` if the roles must be stripped as well.
7. **Provision before first sign-in.** A person cannot log in until they exist
   here and are not blocked. Create the account first, then tell them to sign in.

## Confirm first

Ask the user to confirm before: `users_block`, revoking `administrator`, and any
`users_set_roles` that would drop roles the person currently has. State which
roles disappear, then act.

## Reading the result

Success is `{"state": "done", "user": {...}}`, or `{"state": "done", "users": [...],
"total": N}` for `users_list`, or `{"state": "done", "email": "...", "revoked_tokens": N}`
for `users_logout`. `users_block` may add top-level `revoked_tokens` (or `null` if the
token store failed during revoke). Failure is `{"state": "error", "code": "...",
"message": "..."}`.

Report the resulting roles and blocked status back to the user — do not just say
"done".

## Errors

| Code | Meaning | Action |
| --- | --- | --- |
| `user_not_found` | No such email | Check spelling; retry `users_list` with `{"is_blocked": true}` |
| `conflict` | Already exists, or role already present | Read current state with `users_list`; usually nothing to do |
| `validation_error` | Missing or malformed argument, unknown role | Fix the argument; verify the role exists in the deployment's RBAC policy |
| `last_administrator` | Would leave no active administrator | Refuse; ask for another administrator to be appointed first |
| `self_admin_mutation_forbidden` | Actor is removing their own administrator access | Refuse; another administrator must do it |
| `forbidden` | Caller is not an administrator | Stop and report; do not retry |
| `service_timeout`, `service_unavailable` | Directory unreachable | Report it; see the retry rule below |
| `service_unconfigured` | Server is missing directory settings | Report to whoever operates the server |

**Never retry a failed mutation blindly.** A timeout may mean the change was
applied. Call `users_list` first to see the current state, then decide.

## Examples

**"Make Ivan an administrator"** — new person, name known:

```
users_add {"email": "ivan@example.com", "full_name": "Ivan Petrov", "roles": ["administrator"]}
```

**"Ivan already exists; grant administrator and keep his other roles"** —
additive change:

```
users_grant_role {"email": "ivan@example.com", "role": "administrator"}
```

Not `users_set_roles` with only `["administrator"]` when other roles must
stay. `users_set_roles` replaces the whole set and drops every role that is
not listed.

**"Ivan is leaving"** — confirm, then:

```
users_block {"email": "ivan@example.com"}
```

**"Who has admin rights?"**:

```
users_list {"role": "administrator"}
```
