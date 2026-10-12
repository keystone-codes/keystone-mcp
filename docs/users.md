# Users

Keystone-MCP keeps its own list of people: who they are, which roles they
hold, and whether they are blocked. The policy file decides, for each role,
which tools it may call. The users directory decides who the person is,
their roles, and their block state. An email has to exist in the directory,
and not be blocked, before that person's first sign-in — signing in never
creates an account.

The directory's storage is a SQLite file for a single host, or PostgreSQL
for production and for more than one replica. See
[environment.md](environment.md#users-directory) for the variables
(`KEYSTONE_MCP_USERS_BACKEND`, `KEYSTONE_MCP_USERS_DB_URL`, and the rest).
Migrations run automatically on startup; on PostgreSQL, several replicas
starting at once do this safely.

## Roles come from the policy file

A role is a name in the RBAC policy file
([`config/rbac-policy.yaml`](../config/rbac-policy.yaml), or wherever
`KEYSTONE_MCP_RBAC_POLICY_PATH` points), together with the list of tool
patterns that name may call. A role can be assigned to a person only if that
name is already in the file; otherwise the attempt fails with
`validation_error` and the message `unknown role: <name>`.

`administrator` is reserved and always accepted, even if it were ever
missing from the file — the "last administrator" rule and emergency recovery
depend on it existing. The shipped policy defines that one role, plus a
commented-out example of a second one (`member`, limited to a couple of
tools) to copy and adapt. The format is
[rbac-policy-format.md](rbac-policy-format.md).

A change to the policy file takes effect on `SIGHUP` (`kill -HUP <pid>`),
not a new process and not a new account. Names added this way work on the
next call. A role removed from the file is **not** stripped from the people
who hold it, but it stops granting anything; remove it from a person
explicitly with `users_revoke_role` if you want it gone.

## The first administrator

Set `KEYSTONE_MCP_SUPERADMIN_EMAIL` to that person's email before the first
start. On every start, Keystone-MCP creates that account if it does not
exist yet and grants it `administrator`; a repeat start does not duplicate
the account, and if the account was blocked, this seeding does **not**
lift the block. The account's full name is the email address until changed
with `users_update`. To stop this re-granting, remove the variable.

Until a second administrator exists, this is the only person who can add
anyone else.

## If the administrator account is lost

Recover it on the server host, not through the agent:

```bash
keystone-mcp users grant-admin --email recovery@example.com
```

Inside a container:

```bash
docker compose exec <service> keystone-mcp users grant-admin --email recovery@example.com
```

This command needs the same `KEYSTONE_MCP_USERS_DB_URL` the running server
uses, and it prints which database it is about to write to before touching
it. It creates the account if missing, grants `administrator`, and lifts any
block.

Two things are refused even for an administrator: blocking or demoting the
last active administrator, and an administrator removing their own
`administrator` role. Another administrator has to do either of those.

## Adding people through the agent

After the first administrator is signed in, people are added by asking the
agent. The agent calls the built-in `users_*` tools; the acting
administrator is always taken from the signed-in session, never from a tool
argument — do not pass one, and do not ask the agent to pass one.

These tools are published only when `KEYSTONE_MCP_RBAC_MODE=enforce`. With
`off` or `observe` they do not exist at all, and the server says so in its
startup log — there is no mode where they are reachable without
authorization. With `enforce`, only a role whose allow patterns include
`users_*` can see or call them; in the shipped policy that is
`administrator`.

The agent's checklist is the skill
[`skills/keystone-user-admin/SKILL.md`](../skills/keystone-user-admin/SKILL.md).
Copy that folder into the skills directory of the client the administrator
uses (for Claude Code, `~/.claude/skills/keystone-user-admin`). The skill
tells the agent which tool matches which request, when to ask before a
destructive change, and how to read an error.

Changes apply on the next call. The person being added does not need a new
server process. They do need an account that exists and is not blocked
before their own first sign-in.

| Request | Tool |
|---|---|
| List people (blocked accounts are hidden unless asked) | `users_list` |
| Create an account | `users_add` with `email`, `full_name`, and `roles` |
| Add one role and keep the rest | `users_grant_role` |
| Remove one role and keep the rest | `users_revoke_role` |
| Replace the whole role set | `users_set_roles` |
| Change the name or the note | `users_update` |
| Take away access | `users_block` |
| Give access back | `users_unblock` |

There is no delete. Removing a person means `users_block`.

Confirm with the administrator before blocking someone, before revoking
`administrator`, and before `users_set_roles` when that call would drop a
role the person currently has.

A failed mutation is not retried blindly. A timeout may mean the change was
applied. List the person first, then decide.

### Directories that cannot be administered

The built-in directory and the HTTP directory both support administration.
A directory that only reads (the deprecated `UserDirectoryBackend` wrapper
from a 0.4.0 fork, or a read-only plugin directory) publishes `users_list`
alone — the other seven tools above are not published at all, rather than
answering with an error. See
[user-directory.md](user-directory.md#writing-your-own-directory) for what a
directory declares about itself.

## Errors

| Code | What it means |
|---|---|
| `user_not_found` | No such email. Check blocked accounts with `users_list`. |
| `conflict` | The account or the role is already there. |
| `validation_error` | A required argument is missing, or the role is not in the policy file. |
| `last_administrator` | This would leave no active administrator. |
| `self_admin_mutation_forbidden` | The signed-in administrator is removing their own administrator access. |
| `forbidden` | The caller is not allowed to manage users. |
| `service_unconfigured` | Built-in directory: the store is not wired (report a bug). HTTP directory: `KEYSTONE_MCP_USERS_SERVICE_URL` or the token is empty. |
| `service_timeout` | The request to an HTTP directory timed out. |
| `service_unavailable` | The users database (or, with the HTTP directory, the service) did not answer. |

## Moving from an external users directory

Keystone-MCP used to delegate to a separate users directory service. If
`KEYSTONE_MCP_USERS_SERVICE_URL` is set and `KEYSTONE_MCP_USERS_BACKEND` is
not, startup now refuses to run rather than silently starting against an
empty, brand-new local database — set `KEYSTONE_MCP_USERS_BACKEND`
explicitly — `http` to keep the external service, `local` to move to the
built-in directory.

To move an existing deployment onto the built-in directory:

1. Stop making changes to people in the old directory.
2. On the Keystone-MCP host, set `KEYSTONE_MCP_USERS_DB_URL` (a PostgreSQL
   URL for production).
3. Run `keystone-mcp users import --from-url <old directory URL> --policy
   <policy path> --dry-run` and read the output: it lists which roles would
   be skipped because they are not in your policy file (add them to the
   policy first, or accept that those people lose that role on import), and
   the count `admin_or_block_changes`, i.e. how many people already imported
   once would have a block lifted *or re-applied*, `administrator`
   granted/revoked, or any other locally granted role revoked, to match the
   source on this run.
4. Run the same command again without `--dry-run`. **The source directory is
   authoritative on every run, not only the first**: re-running `import`
   later overwrites a person's block state and roles again to match the
   source, even if someone changed them locally (through `users_*`) in the
   meantime — it is not a one-time snapshot. That includes re-blocking
   someone who was unblocked locally, and silently dropping a role granted
   locally (including `administrator`) that the source does not report.
   Check `admin_or_block_changes` in the output before re-running against a
   directory people have already been managed in locally.
5. Remove `KEYSTONE_MCP_USERS_SERVICE_URL`, `KEYSTONE_MCP_USERS_SERVICE_TOKEN`,
   and `KEYSTONE_MCP_USERS_BACKEND=http` if they were set, and restart
   Keystone-MCP.
6. Sign in as an administrator, confirm `users_list` shows the people you
   expect, then stop the old service.

A source record `import` cannot write (an invalid email, a `full_name` over
255 characters, or a malformed role) is skipped rather than aborting the
whole run; it is named in the output (`skipped_invalid=N`) with the reason,
never with the source's raw payload or the token.

Keeping the external directory instead of importing is also possible: set
`KEYSTONE_MCP_USERS_BACKEND=http` and leave it there. That path exists for
forks that already run their own users service; error codes coming back
from it are passed through close to as-is and can differ in detail from the
table above (built against the built-in directory).

## `grant-admin` and a brand-new database

Both `keystone-mcp users grant-admin` and `keystone-mcp users import` print
`Users directory: sqlite:///<absolute path>` (or the redacted PostgreSQL URL)
before touching anything, so an operator can see at a glance which database a
command is about to use — important because the default
`KEYSTONE_MCP_USERS_DB_URL` is a path *relative to the current working
directory*, not necessarily the server's. When that SQLite file does not
exist yet, both commands warn that a new, empty database will be created
there; `grant-admin` additionally refuses to proceed unless `--create` is
passed, since silently creating (and writing the new administrator into) an
unrelated, empty database is exactly the failure mode a break-glass recovery
command run from the wrong directory would otherwise hit. `import` has no
such flag: writing into a fresh database is its normal first use.
