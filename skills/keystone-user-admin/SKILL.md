---
name: keystone-user-admin
description: Manage Keystone-MCP users, service accounts, API keys and roles — add, update, block/unblock, grant, revoke or replace roles, create a service account, revoke an API key, or delete a person when they ask for erasure. Use when asked to give someone access, change a role, disable a user, create a service account, revoke an API key, or remove personal data in Keystone-MCP.
---

# Keystone-MCP user and role administration

The Keystone-MCP connector exposes built-in `users_*`, `service_accounts_*`, and
`api_keys_*` tools backed by the shared users directory. Pick the tool from the
tables below and call it once with exactly the listed arguments. Do not probe
other tools and do not guess argument names.

When the RBAC policy refuses a tool (your roles do not allow it), the MCP client
gets a tool error with text like **access denied** — not a
`{"state": "error", "code": "..."}` envelope from the adapter.

Only a **full administrator** (every administration tool allowed by policy,
whatever the role names) may grant or revoke a **management role**, change,
block, unblock, log out, delete a person, or manage API keys for an account that
holds a management role. Other allowed changes follow ordinary RBAC. Changes take
effect immediately — no restart or re-login is needed on the server side.

## Roles

Role names come from the deployment's RBAC policy file
(`KEYSTONE_MCP_RBAC_POLICY_PATH`; see `docs/rbac-policy-format.md` and
`config/rbac-policy.yaml`). Roles are declared in that file; change them with
the `keystone-policy-admin` skill (the `policy_*` tools), not here. Do not
invent a role name while adding a person — read the current roles with
`policy_read` or ask. The directory and the policy must use the same strings.

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
| Revoke access | `users_block` | `{"email": "..."}` — blocks the person and revokes OAuth sessions (`revoked_tokens` on success) |
| End sessions only | `users_logout` | `{"email": "..."}` — revokes tokens; person can sign in again; directory entry not required |
| Restore access | `users_unblock` | `{"email": "..."}` — does not restore old sessions |
| Delete or anonymize a person | `users_delete` | `{"email": "..."}` — see below; irreversible |
| Export everything Keystone holds about a person | `users_export` | `{"email": "..."}` — see below; full administrators only |

## Service accounts

Machine callers use subject `svc:<name>`. Only a human full administrator may
create or change them (`service_accounts_*` mutations are refused for service
accounts in code).

| Request | Tool | Arguments |
| --- | --- | --- |
| List service accounts | `service_accounts_list` | `{}` or `{"is_blocked": true}` |
| Create a service account | `service_accounts_add` | `{"name": "...", "roles": ["..."], "description": "..."}` — `roles` and `description` optional |
| Change roles, description, or block | `service_accounts_update` | `{"name": "...", "roles": [...], "description": "...", "is_blocked": true}` — send only fields that change |

Service accounts cannot hold the `administrator` role (or any role that would
make them a full administrator). Issue API keys for them with `api_keys_issue`
or the operator CLI.

## API keys

| Request | Tool | Arguments |
| --- | --- | --- |
| Issue a key (secret shown once) | `api_keys_issue` | `{"subject": "person@example.com"}` or `{"subject": "svc:ci", "label": "...", "expires_in_days": 90}` — not published in `production`; use `keystone-mcp keys issue` there |
| List keys (no secrets) | `api_keys_list` | `{}` or `{"subject": "...", "include_revoked": true}` |
| Revoke a key | `api_keys_revoke` | `{"key_id": "..."}` — ends Bearer use and sign-in sessions opened with that key |

Confirm before `api_keys_revoke`. On success the response includes
`revoked_tokens` (session count). If the session store fails during revoke,
you get `service_unavailable` with a retry message while the key is already
revoked.

## `users_export`

Call this when someone asks **what data you store about them** (access /
portability), not for routine directory browsing (`users_list` is broader and
shows every person).

Only a **full administrator** may call it; service accounts get `forbidden`.
On success: `{"state": "done", "export": {...}}` with `format:
keystone-person-export/1`. Share the `export` object with the requester: it
lists directory fields, API key metadata (no secrets), open session count,
audit pseudonym, and `not_held` (what Keystone does not store). Never paste
raw OAuth tokens or API key secrets — they are not in the export.

## `users_delete`

Call this only when the human explicitly asks to **delete their data** or to
**remove the person from the directory** — not for ordinary offboarding
(`users_block` is the reversible alternative).

1. Call `users_delete` with `{"email": "..."}` only. The server returns
   `state: "confirmation_required"`, a **summary** (roles, keys, sessions), and a
   one-time `confirmation` code.
2. **Show the summary to the human and wait for an explicit “yes”.** Do not
   call step 2 until they agree.
3. Call again with `{"email": "...", "confirmation": "<code>"}` using exactly
   the code from step 1. Never invent or reuse a code.

The deployment mode (`anonymize` vs hard delete) is set by the operator in
`KEYSTONE_MCP_USERS_DELETE_MODE`, not by tool arguments. On success you get
`state: "done"` with `pseudonym` (audit hash). Sessions and API keys are revoked.

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
6. **Offboarding vs erasure.** Routine departure: `users_block` (reversible).
   Erasure or GDPR-style removal: `users_delete` with the two-step flow above.
7. **Provision before first sign-in.** A person cannot log in until they exist
   here and are not blocked. Create the account first, then tell them to sign in.

## Confirm first

Ask the user to confirm before: `users_block`, `users_delete` (step 2 only after
they agree to the summary), revoking `administrator`, and any `users_set_roles`
that would drop roles the person currently has. State which roles disappear, then act.

## Reading the result

Success is `{"state": "done", "user": {...}}`, or `{"state": "done", "users": [...],
"total": N}` for `users_list`, or `{"state": "done", "email": "...", "revoked_tokens": N}`
for `users_logout`, or `{"state": "confirmation_required", ...}` / `{"state": "done",
"pseudonym": "...", ...}` for `users_delete`. Successful `users_block` and
`users_logout` include `revoked_tokens` (count). `users_grant_role` /
`users_revoke_role` return `changed: false` when the role was already present or
absent. Failure is `{"state": "error", "code": "...", "message": "..."}`.

If `users_block` blocked the person but could not reach the session store, you
get `service_unavailable` with a message that sessions were not revoked — the
person is already blocked. Call `users_block` again; it is safe to repeat.

Report the resulting roles and blocked status back to the user — do not just say
"done".

## Errors

| Code | Meaning | Action |
| --- | --- | --- |
| `actor_email_required` | The server could not tell who you are | Sign in again as a human administrator |
| `user_not_found` | No such email or service account | Check spelling; retry `users_list` or `service_accounts_list` with `{"is_blocked": true}` |
| `conflict` | Person or service account already exists, including when two writes race on the same email or role | Read current state; usually nothing to do — not a directory outage |
| `validation_error` | Missing or malformed argument, unknown role | Fix the argument; verify the role exists in the deployment's RBAC policy |
| `bad_request` | The external users directory rejected the request | Report it to whoever operates the directory; do not retry blindly |
| `service_error` | The external users directory returned an unexpected error | Report it to whoever operates the directory; do not retry blindly |
| `last_administrator` | Would leave no active full administrator | Refuse; ask for another full administrator to be appointed first |
| `self_admin_mutation_forbidden` | Actor is removing their own full administrator access | Refuse; another full administrator must do it |
| `forbidden` | You are not a full administrator, and the change touches a management role or a person/service account holding one, or the role gives permissions you do not have yourself; or a service account called a mutating admin tool. Stop and report; do not retry. |
| `service_timeout` | Directory timed out | Report it; see the retry rule below |
| `service_unavailable` | Directory or session store unreachable | Report it; see the retry rule below |
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
