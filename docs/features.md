# What Keystone-MCP does

Keystone-MCP is one layer in front of an agent application, with three
jobs: it is the **facade** the client talks to, the **router** that
forwards each call to the service that owns it, and the **authorization**
layer that decides what the signed-in person may see and call. This page
goes one level deeper than the README on every capability that supports
that, and says plainly which parts are still ahead, in 0.5.0.

## One facade

A client — Claude Desktop, Cursor, Claude Code, or any other MCP client —
connects to one address and sees one tool catalog. The catalog is split
into sections, one per upstream service, named `<namespace>_<tool>`. How
sections, discovery and the proxy work: [facade.md](facade.md).

## Any users directory

Keystone-MCP keeps its own list of people — email, roles, blocked or not.
By default it is built in: a SQLite file for a single host, or PostgreSQL
for production and more than one replica. A fork that already runs its own
users service can point `KEYSTONE_MCP_USERS_BACKEND=http` at it instead and
keep using that directory. Both are implementations of one `UserDirectory`
protocol — read access (`resolve_user`, `list_users`) plus an optional
`UserDirectoryAdmin` capability that wires up the `users_*` tools; a
directory that cannot administer still publishes `users_list`. Either way,
the rest of Keystone-MCP (sign-in, RBAC, the `users_*` tools) works the
same. Details: [users.md](users.md) and, for the protocol itself and the
HTTP contract a fork's own directory must meet,
[user-directory.md](user-directory.md).

## Any sign-in method

Today a person signs in with Google (the production method) or with a DEV
token (local testing only — a shared password accepted under the `local`
profile). A deprecated API-key method still exists for one more release.
There is no common plugin interface for identity providers yet: adding a
third one means writing to the `IdentityProvider` protocol directly (see
[adding-routes.md](adding-routes.md#extending-keystone-mcp-in-a-fork)). A
general way to register your own identity provider without touching that
code is planned for **0.5.0**.

## Onboarding and access management through the agent

An administrator does not edit a database by hand. They ask the agent to
add a person, change a role, or block someone, and the agent calls the
built-in `users_*` tools — `users_add`, `users_grant_role`,
`users_revoke_role`, `users_set_roles`, `users_update`, `users_block`,
`users_unblock`, `users_list`. The checklist the agent follows is the
[`keystone-user-admin`](../skills/keystone-user-admin/SKILL.md) skill. The
first administrator, and every later one from a fresh deployment, can come
from `setup.sh --non-interactive` reading `KEYSTONE_SETUP_*` variables —
see [deploy.md](deploy.md). In 0.4.0 the *access policy itself* (which
role may call which tools) is still a file an operator edits by hand;
the agent manages people and roles, not the policy file. Full reference:
[users.md](users.md).

## Services in any language or SDK

A service behind Keystone-MCP is a plain MCP server over Streamable HTTP.
It can be written in any language, with any MCP SDK, with its own storage
and its own integrations. Keystone-MCP only needs its URL, a namespace, and
optionally a bearer token to authenticate back to it. Contract:
[connecting-services.md](connecting-services.md).

A service can also be a local process instead of a network one: a registry
entry with `transport: stdio` names a `command`, its `args`, and the names
of the environment variables it needs (never their values) — the shape
most ready-made MCP servers from npm or pip come in. Keystone-MCP's
registry and supervisor already start that process, keep it alive, and
restart it with a backoff after a crash or a hang; proxying calls to it
lands with the stdio wiring.

A long-running tool can report progress while it runs
(`notifications/progress`); Keystone-MCP relays every update to the client,
in the same call, exactly as the upstream sent it — see "What passes
through the door" in [facade.md](facade.md#what-passes-through-the-door).

## One policy file, reloaded live

Access rules — which role may call which tool patterns — live in one YAML
file (`KEYSTONE_MCP_RBAC_POLICY_PATH`). Editing it and sending `SIGHUP`
applies the change immediately, with no restart and no new deployment.
Format: [rbac-policy-format.md](rbac-policy-format.md).

## Services never check roles themselves

RBAC is decided once, on Keystone-MCP, before a call is ever forwarded. A
proxied call carries the verified `X-Author-Email` of the signed-in
person, never a role — the service trusts that header only on a network
Keystone-MCP alone controls. Details: [security-model.md](security-model.md).

## `production` refuses a weak configuration

The `production` deployment profile is not a suggestion: startup refuses
to run with DEV tokens set, with a SQLite users directory, or with a
plain-`http` `KEYSTONE_MCP_BASE_URL` on a publicly reachable host. The
full rule table is in
[environment.md](environment.md#deployment-profile).

## Metrics and audit

Prometheus metrics (RBAC decisions, tool calls, catalog refresh, users
mutations) and structured audit events for every authorization decision
and every `users_*` mutation ship with the process. Details:
[observability-rbac.md](observability-rbac.md) and
[observability-logging.md](observability-logging.md).

## One image, two architectures

The published container image is multi-arch: `linux/amd64` and
`linux/arm64`, so it runs the same on a cloud VM and on Apple Silicon.

## A demo in about 15 minutes

`docker compose -f docker-compose.demo.yml up -d --build --wait` starts
Keystone-MCP, Redis, and a sample upstream service, with a policy that
shows the whole facade/router/authorization story in one sitting. Walk
through: [paths/local-compose.md](paths/local-compose.md).

## Related

- [docs/README.md](README.md) — every guide, grouped by who reads it
- [security-model.md](security-model.md) — the three things that decide access
- [adding-routes.md](adding-routes.md) — what a fork can already replace, and
  what is not pluggable yet
