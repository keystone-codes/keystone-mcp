"""The ``UserDirectory`` protocol: one interface to read and administer people.

This module imports only the standard library and
:mod:`keystone_mcp.user_directory.types` (see
``tests/test_user_directory_protocol.py::test_protocol_and_types_are_dependency_free``):
a directory implementation can be as small as a dict in memory or a YAML file,
with no ``fastmcp``, ``httpx``, ``sqlalchemy`` or ``redis`` in sight.

Rules every implementation follows (also checked by the contract tests in
``keystone_mcp.contract_tests``, see X11):

* The implementation normalizes ``subject`` on input (``strip().lower()`` for
  an email); every email it returns is already lower-cased.
* ``resolve_user``'s argument is named ``subject``: in this card it is always
  a person's email. A later card (X07) adds service-account identifiers of
  the form ``svc:<name>``; an implementation that does not support those
  answers ``exists=False`` rather than raising.
* ``resolve_user`` for an unknown subject returns
  ``UserResolveResult(exists=False, roles=(), is_blocked=False)`` -- never an
  error. The only errors it raises are
  :class:`~keystone_mcp.user_directory.errors.UserDirectoryUnavailableError`
  (codes ``catalog_unavailable``, ``catalog_timeout``): the directory itself
  could not be reached, not "this subject does not exist".
* Role-against-policy checks are Keystone's job, done *before* calling the
  directory: the directory only checks the format of a role name and its own
  invariants.
* Administrator invariants are the directory's responsibility: it refuses to
  remove the ``administrator`` role from, or block, the last active
  administrator (code ``last_administrator``), and refuses to let an actor
  mutate their own administrator access (comparing ``actor`` to ``email``,
  code ``self_admin_mutation_forbidden``).
* A mutation that changes nothing is not an error: granting an already-held
  role, blocking an already-blocked user, ``update_user`` with the same
  values, or ``replace_roles`` with the same set all return
  ``changed=False`` rather than raising.
* After a successful mutation, the directory is responsible for telling other
  replicas: the built-in directory bumps a revision counter in Redis; an
  external directory does the same through its own revision contract (see
  the HTTP directory's revision header). Keystone never bumps the revision on
  a directory's behalf.
* Every error raised is one of the classes in
  :mod:`keystone_mcp.user_directory.errors`, carrying a ``code`` from the
  table in ``skills/keystone-user-admin/SKILL.md``.

See ``docs/user-directory.md`` for the full writer's guide.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Protocol, runtime_checkable

from keystone_mcp.user_directory.types import (
    ApiKeyRecord,
    ApiKeyVerification,
    IssuedApiKey,
    MutationResult,
    ServiceAccountMutation,
    ServiceAccountRecord,
    UserRecord,
    UserResolveResult,
)

#: What a directory can do beyond reading.
Capability = Literal["admin", "service_accounts", "api_keys"]


@runtime_checkable
class UserDirectory(Protocol):
    """Read side every directory implementation must support.

    ``name`` identifies the implementation in logs and readiness checks
    (``"local"``, ``"http"``, or a plugin's own name). ``capabilities`` is
    what the implementation honestly declares beyond reading -- an empty
    ``frozenset`` means Keystone publishes only ``users_list`` for it (see
    :func:`keystone_mcp.catalog.builtin.register_catalog`).
    """

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
    """Implemented by directories that declare the ``"admin"`` capability.

    A directory that declares ``"admin"`` in ``capabilities`` without
    implementing every method here is a configuration error, refused at
    startup (see :func:`keystone_mcp.user_directory.factory.build_user_directory`).
    """

    async def create_user(
        self,
        *,
        email: str,
        full_name: str,
        roles: Sequence[str],
        note: str | None,
        actor: str,
    ) -> MutationResult: ...

    async def update_user(
        self,
        *,
        email: str,
        full_name: str | None,
        note: str | None,
        actor: str,
    ) -> MutationResult: ...

    async def set_blocked(self, *, email: str, blocked: bool, actor: str) -> MutationResult: ...

    async def replace_roles(
        self, *, email: str, roles: Sequence[str], actor: str
    ) -> MutationResult: ...

    async def grant_role(self, *, email: str, role: str, actor: str) -> MutationResult: ...

    async def revoke_role(self, *, email: str, role: str, actor: str) -> MutationResult: ...


@runtime_checkable
class ServiceAccountDirectory(UserDirectory, Protocol):
    async def list_service_accounts(
        self, *, is_blocked: bool | None = False
    ) -> list[ServiceAccountRecord]: ...

    async def create_service_account(
        self,
        *,
        name: str,
        description: str | None,
        roles: Sequence[str],
        actor: str,
    ) -> ServiceAccountMutation: ...

    async def update_service_account(
        self,
        *,
        name: str,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        is_blocked: bool | None = None,
        actor: str,
    ) -> ServiceAccountMutation: ...


@runtime_checkable
class ApiKeyDirectory(UserDirectory, Protocol):
    async def issue_api_key(
        self,
        *,
        subject: str,
        label: str | None,
        expires_in_days: int | None,
        actor: str,
    ) -> IssuedApiKey: ...

    async def list_api_keys(
        self,
        *,
        subject: str | None = None,
        include_revoked: bool = False,
    ) -> list[ApiKeyRecord]: ...

    async def revoke_api_key(self, *, key_id: str, actor: str) -> tuple[ApiKeyRecord, bool]: ...

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None: ...


@runtime_checkable
class ApiKeyIdIndex(Protocol):
    """Optional: a directory that can list the key ids of its active API keys.

    Lets the resolver refuse an unknown key id without calling the directory
    and without caching anything for it.
    """

    async def active_api_key_ids(self) -> frozenset[str]: ...


@runtime_checkable
class UserDirectoryBackend(Protocol):
    """Deprecated: a read-only, single-method directory client (0.4.0).

    Implement :class:`UserDirectory` instead. A :class:`UserDirectoryBackend`
    passed to
    :func:`keystone_mcp.user_directory.factory.build_user_directory_resolver`
    (its old ``backend=`` keyword) is still accepted, wrapped in
    :class:`keystone_mcp.user_directory.compat.ReadOnlyBackendDirectory`, with
    a :class:`DeprecationWarning`. Deprecated since 0.5.0, removed in 2.0.
    """

    async def resolve_user(self, email: str) -> UserResolveResult: ...

    async def aclose(self) -> None: ...


@runtime_checkable
class UserDirectoryResolver(Protocol):
    """Cached fail-closed resolver used by login and RBAC enforcement."""

    async def resolve(self, email: str, *, critical: bool = False) -> UserResolveResult: ...

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None: ...

    async def aclose(self) -> None: ...
