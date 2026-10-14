# The `UserDirectory` protocol

Keystone-MCP keeps one list of people allowed to sign in, and the roles each
one has: the **users directory**. It answers two questions for every
deployment — "who may sign in, and with which roles" (used by login and by
RBAC on every tool call) and, optionally, "who may change that" (the
`users_*` tools an administrator calls through the agent). Both are one
Python protocol, `keystone_mcp.user_directory.UserDirectory`, so a deployment
can swap the directory itself — the built-in database, an external HTTP
service, or a directory written for a fork — without touching login, RBAC,
or the `users_*` tools.

## The protocol

```python
from typing import Literal, Protocol, runtime_checkable

Capability = Literal["admin"]


@runtime_checkable
class UserDirectory(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def capabilities(self) -> frozenset[str]: ...
    async def resolve_user(self, subject: str) -> UserResolveResult: ...
    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]: ...
    async def ping(self) -> None: ...
    async def aclose(self) -> None: ...


@runtime_checkable
class UserDirectoryAdmin(UserDirectory, Protocol):
    async def create_user(
        self, *, email: str, full_name: str, roles: Sequence[str], note: str | None, actor: str
    ) -> MutationResult: ...
    async def update_user(
        self, *, email: str, full_name: str | None, note: str | None, actor: str
    ) -> MutationResult: ...
    async def set_blocked(self, *, email: str, blocked: bool, actor: str) -> MutationResult: ...
    async def replace_roles(
        self, *, email: str, roles: Sequence[str], actor: str
    ) -> MutationResult: ...
    async def grant_role(self, *, email: str, role: str, actor: str) -> MutationResult: ...
    async def revoke_role(self, *, email: str, role: str, actor: str) -> MutationResult: ...
```

Every directory implements `UserDirectory`. `UserDirectoryAdmin` is optional:
a directory declares what it supports through `capabilities` (today the only
value is `"admin"`), and Keystone checks that declaration against the actual
class at startup — a directory that claims `"admin"` without implementing
every method above is refused rather than failing on the first `users_*`
call.

**Rules every implementation follows** (checked by the [contract tests](plugins.md#contract-tests)
in `keystone_mcp.contract_tests` and the [plugin template](plugins.md#plugin-template)):

- Normalize the subject on input (`strip().lower()` for an email); every
  email returned is already lower-cased.
- `resolve_user`'s argument is named `subject`, not `email`: in this release
  it is always a person's email, but a service-account directory (a later
  release) answers it too, with an identifier of the form `svc:<name>`. An
  implementation that only knows about people answers `exists=False` for
  anything it does not recognize — it never raises for an unknown subject.
- `resolve_user` never raises for an unknown subject — only for an
  unreachable directory
  (`UserDirectoryUnavailableError`, codes `catalog_unavailable` /
  `catalog_timeout`).
- Role-against-policy checks are Keystone's job, done before the directory
  is ever called. The directory only checks the *format* of a role name
  (reject empty or over-length names) and its own invariants.
- Administrator invariants are the directory's job: refuse to remove
  `administrator` from, or block, the last active administrator
  (`last_administrator`), and refuse to let an actor mutate their own
  administrator access (`self_admin_mutation_forbidden`).
- A mutation that changes nothing is not an error — granting an
  already-held role, blocking an already-blocked user, `update_user` with
  the same values, `replace_roles` with the same set — all return
  `MutationResult(changed=False, ...)`.
- After a successful mutation, the directory tells other replicas itself
  (see "Revision and caching" below); Keystone never bumps that counter on
  a directory's behalf.
- Every error raised is one of the classes in `keystone_mcp.user_directory.errors`,
  with a `code` from the table below.

## Writing your own directory

A read-only directory — people and roles from a YAML file, say — needs only
the four `UserDirectory` methods; declaring no capabilities means Keystone
publishes `users_list` for it and nothing else (see
[users.md](users.md#directories-that-cannot-be-administered)):

```python
import yaml
from keystone_mcp.user_directory import UserRecord, UserResolveResult
from datetime import datetime, UTC


class StaticFileUserDirectory:
    """Read-only: people and roles come from one YAML file, reloaded per call."""

    def __init__(self, path: str) -> None:
        self._path = path

    @property
    def name(self) -> str:
        return "static-file"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset()  # read-only: users_list only, no admin tools

    def _load(self) -> dict:
        with open(self._path, encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    async def resolve_user(self, subject: str) -> UserResolveResult:
        entry = self._load().get(subject.strip().lower())
        if entry is None:
            return UserResolveResult(exists=False, roles=(), is_blocked=False)
        return UserResolveResult(
            exists=True,
            roles=tuple(entry.get("roles", ())),
            is_blocked=bool(entry.get("is_blocked", False)),
        )

    async def list_users(self, *, is_blocked=False, role=None, email_contains=None):
        now = datetime.now(UTC)
        return [
            UserRecord(
                email=email,
                full_name=entry.get("full_name", email),
                roles=tuple(entry.get("roles", ())),
                is_blocked=bool(entry.get("is_blocked", False)),
                created_at=now,
                updated_at=now,
                created_by=None,
                note=None,
            )
            for email, entry in self._load().items()
            if is_blocked is None or bool(entry.get("is_blocked", False)) == is_blocked
        ]

    async def ping(self) -> None:
        self._load()  # raises if the file is missing or unparsable

    async def aclose(self) -> None:
        return None
```

A richer example (LDAP, a ticketing system's user table) looks the same
shape, just backed by a real connection instead of a file. Registering a
directory from your own package without editing Keystone's core: see
plugins.md.

## Errors

| Code | Meaning |
|---|---|
| `user_not_found` | No such email. |
| `conflict` | The account, or the role being granted, already exists. |
| `validation_error` | A required argument is missing, or the role name's format is invalid. |
| `last_administrator` | The change would leave no active administrator. |
| `self_admin_mutation_forbidden` | An administrator tried to mutate their own administrator access. |
| `actor_email_required` | A mutation that needs an acting administrator's email did not get one. |
| `forbidden` | The actor may not manage users (HTTP directory only). |
| `service_unconfigured` | No directory is configured, or it does not support administration. |
| `service_timeout` | The directory's administration path timed out. |
| `service_unavailable` | The directory (database or external service) did not answer. |
| `service_error` | The directory (HTTP backend) answered with a response this client could not parse (an unrecognized status, an empty or malformed body, or a record missing a required field). |
| `catalog_unavailable` / `catalog_timeout` | The read path (`resolve_user`/`ping`) could not reach the directory — fail-closed for login and RBAC. |

## The HTTP directory contract

With `KEYSTONE_MCP_USERS_BACKEND=http`, Keystone calls the external service
with `Authorization: Bearer <KEYSTONE_MCP_USERS_SERVICE_TOKEN>`; every email
in a path or a query parameter is lower-cased first; every administration
call additionally carries `X-Actor-Email` set to the verified email of the
signed-in administrator, and the service is responsible for checking that
this actor is itself allowed to manage users.

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/v1/users/resolve?email=` | — | `{"exists": bool, "roles": [...], "is_blocked": bool}` |
| `GET` | `/v1/users?is_blocked=&role=&email_contains=` | — | `{"users": [...], "total": N}` |
| `POST` | `/v1/users` | `{"email", "full_name", "roles": [...], "created_by", "note"?}` | user object |
| `PATCH` | `/v1/users/{email}` | `{"full_name"?, "note"?}` | user object |
| `POST` | `/v1/users/{email}/block` | — | user object |
| `POST` | `/v1/users/{email}/unblock` | — | user object |
| `PUT` | `/v1/users/{email}/roles` | `{"roles": [...]}` | user object |
| `POST` | `/v1/users/{email}/roles/{role}` | — | user object (grant) |
| `DELETE` | `/v1/users/{email}/roles/{role}` | — | user object (revoke) |

(Endpoints and bodies: `src/keystone_mcp/user_directory/http.py`; email path
segments are percent-encoded.) The user object has eight fields: `email`,
`full_name`, `roles`, `is_blocked`, `created_at`, `updated_at` (ISO 8601,
`Z` suffix), `created_by`, `note`.

**Code normalization.** `HttpUserDirectory` normalizes two of
the service's own codes onto the table above before Keystone ever sees them:
`invalid_role` becomes `validation_error`, `user_already_exists` becomes
`conflict`. Every other code the service reports passes through unchanged —
a fork's HTTP service should raise the codes in the table directly rather
than inventing its own, except for those two legacy spellings, which
existing deployments of the external service may still use.

See [users.md](users.md#errors) for the same table as an administrator sees
it through the agent.

## Revision and caching

A directory is responsible for telling other Keystone replicas when
something changed. The built-in directory bumps an integer at
`KEYSTONE_MCP_USERS_REDIS_REVISION_KEY` (default `km:users:revision`) in
Redis after every successful mutation; the external HTTP service does the
same thing on its own side of that same Redis instance. Keystone's cache
(`CachedUserDirectoryResolver`) watches that counter: when it changes, every
cached resolution is dropped and the next call re-reads the directory.

A directory that forgets to bump the revision does not break immediately —
callers keep seeing the cached (now stale) answer for up to
`KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS` (default 60) seconds for an
allowed decision, or `KEYSTONE_MCP_USERS_CACHE_DENY_TTL_SECONDS` for a denial,
after which the cache expires on its own and the next call reads fresh data
regardless.

API key verification uses separate positive and negative caches (each capped
at 10 000 entries) plus a resolution cache (50 000 subjects). The built-in
directory also implements optional `ApiKeyIdIndex`: Keystone loads the set of
active `key_id` values (refreshed on revision change and at least every
`KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS`) so unknown ids are refused
without a database round-trip. Directories without that protocol fall back to
a per-process rate limit (20/s, burst 50) for `key_id` values that have never
verified successfully on that replica.

## Registering a directory from your own package

See [plugins.md](plugins.md). Why: [ADR 0009](adr/0009-plugins-via-entry-points.md).
