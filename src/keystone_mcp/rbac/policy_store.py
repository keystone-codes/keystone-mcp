"""Read and change the RBAC policy file from inside the process.

``PolicyStore`` is the core the ``policy_*`` MCP tools wrap in
a thin adapter. It reuses the exact validation the hot-reload path
(``RbacPolicyManager.reload``) already runs -- :func:`~keystone_mcp.rbac.loader
.assert_live_catalog_validation` -- so a change accepted here can never fail
the very next ``SIGHUP`` or background reload, and a change this refuses is
refused for the same reason a hand-edited file would be.

Write path, in order (see :meth:`PolicyStore.change`):

1. Refuse when ``KEYSTONE_MCP_POLICY_TOOLS`` is not ``"full"``, or the file
   (or its directory) is not writable -- ``policy_readonly``.
2. Read the *file* (not the active snapshot) and check ``expected_hash``
   (optimistic locking) -- ``policy_conflict``.
3. Apply every :class:`~keystone_mcp.rbac.policy_document.PolicyChange` to a
   copy; if nothing actually changed, return ``changed=False`` without
   touching the file.
4. Validate the candidate with the same structural and live-catalog gate as a
   hot-reload -- ``policy_invalid`` / ``unmatched_pattern``.
5. Run the invariants (:mod:`keystone_mcp.rbac.policy_invariants`).
6. Write atomically with unique temp files, ``fsync``, copy the
   current file to ``.bak`` (one generation, overwritten), ``os.replace``.
7. Reload in place through the same ``RbacPolicyManager`` the rest of the
   process reads from. A reload failure restores the previous bytes and refuses
   with ``policy_invalid``.
8. Audit (``rbac_policy_mutation``) and the ``keystone_mcp_policy_mutation_total``
   metric, whatever the outcome.

Hand-written YAML comments are never preserved (see
``keystone_mcp.rbac.policy_document``); the file as it was before this write
survives in ``.bak``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from keystone_mcp.rbac.loader import (
    PolicyLoadError,
    assert_live_catalog_validation,
    live_catalog_names,
    split_unverified_allow_patterns,
)
from keystone_mcp.rbac.management import (
    ManagementView,
    management_change_reasons,
)
from keystone_mcp.rbac.policy import (
    PolicyContractError,
    RbacPolicy,
    hash_policy_bytes,
    validate_policy_against_catalog,
    validate_policy_structure,
)
from keystone_mcp.rbac.policy_document import (
    PolicyChange,
    PolicyChangeError,
    PolicyDocument,
    RoleDelete,
    describe_changes,
)
from keystone_mcp.rbac.policy_invariants import (
    check_full_administrator_remains,
    check_no_role_can_administer,
    check_role_in_use,
    check_self_lockout_forbidden,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from keystone_mcp.config import Settings
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.rbac.policy_revision import PolicyRevisionWatcher
    from keystone_mcp.router.registry import RouterRegistry
    from keystone_mcp.user_directory.protocol import UserDirectory

logger = logging.getLogger(__name__)

__all__ = [
    "PolicyStore",
    "PolicyReadResult",
    "PolicyValidationResult",
    "PolicyChangeResult",
]


@dataclass(frozen=True, slots=True)
class PolicyReadResult:
    """Current policy file, plus enough to detect drift and build a write."""

    document: PolicyDocument
    #: ``RbacPolicyManager.identity.content_hash`` of the currently *active*
    #: (loaded) policy snapshot -- ``None`` if none has been loaded yet.
    content_hash: str | None
    #: SHA-256 of the bytes just read from the file on disk. Differs from
    #: ``content_hash`` when the file changed outside the policy tools and
    #: has not been reloaded yet (hand edit, or another replica's write on a
    #: shared volume ahead of this process's next reconciler tick).
    file_hash: str
    path: Path
    writable: bool
    unreachable_tools: frozenset[str]
    unverified_patterns: dict[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class PolicyValidationResult:
    """Outcome of a dry-run validation; never writes anything."""

    ok: bool
    errors: tuple[str, ...]
    unreachable_tools: frozenset[str]
    unverified_patterns: dict[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class PolicyChangeResult:
    """Outcome of a successful :meth:`PolicyStore.change` or ``.rollback``.

    A refused or failed attempt raises :class:`PolicyChangeError` instead of
    returning this with ``changed=False`` -- the sole exception is a change
    set that, applied, is a genuine no-op (every pattern already present/absent):
    that is not an error, and this is returned with ``changed=False``.
    """

    changed: bool
    document: PolicyDocument
    content_hash_before: str
    content_hash_after: str
    warnings: tuple[str, ...] = ()
    reloaded: bool = False


def _default_clock() -> datetime:
    return datetime.now(UTC)


class _ReloadFailedAfterWrite(PolicyChangeError):
    """A write succeeded but the in-place reload of it then failed.

    Distinct *type* from a plain :class:`PolicyChangeError` only so
    :meth:`PolicyStore.change`/``.rollback`` can audit it as ``outcome="error"``
    (an unexpected, already-partially-applied failure) rather than
    ``"refused"`` (never attempted). Its ``.code`` is still ``"policy_invalid"``
    -- the one code callers of this module are promised.
    """

    def __init__(self, message: str) -> None:
        super().__init__("policy_invalid", message)


class _WriteFailed(PolicyChangeError):
    """Disk write failed during a policy mutation."""

    def __init__(self, message: str) -> None:
        super().__init__("service_unavailable", message)


def _fsync_directory(directory: Path) -> None:
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError as exc:
        logger.debug("policy directory fsync skipped: %s", exc)
        return
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        logger.debug("policy directory fsync skipped: %s", exc)
    finally:
        os.close(dir_fd)


def _atomic_write(path: Path, data: bytes, *, mode_from: Path | None = None) -> None:
    fd, tmp_path_str = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode_from is not None:
            shutil.copymode(mode_from, tmp_path)
        os.replace(tmp_path, path)
        _fsync_directory(path.parent)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise


def _write_with_backup(path: Path, new_bytes: bytes, *, backup: bytes) -> None:
    bak_path = path.with_suffix(path.suffix + ".bak")
    _atomic_write(bak_path, backup, mode_from=path)
    _atomic_write(path, new_bytes, mode_from=path)


@dataclass(kw_only=True)
class PolicyStore:
    """Validated, audited read/write access to the RBAC policy file."""

    settings: Settings
    policy_manager: RbacPolicyManager
    registry: RouterRegistry
    observability: RbacObservability | None = None
    directory: UserDirectory | None = None
    revision_watcher: PolicyRevisionWatcher | None = None
    interactive_login_available: bool = True
    clock: Callable[[], datetime] = field(default=_default_clock, repr=False)
    file_lock_timeout_seconds: float = 10.0
    #: Optional hook (set by :func:`keystone_mcp.server.build_server`) to wake the
    #: surface reconciler after a mutation reloads the in-process policy snapshot.
    surface_mutator: Callable[[], None] | None = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _file_lock_warning_logged: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if fcntl is None and not self._file_lock_warning_logged:
            logger.warning(
                "file locking is not available on this platform; "
                "policy writes are serialized only within this process"
            )
            object.__setattr__(self, "_file_lock_warning_logged", True)

    def _live_names(self) -> frozenset[str]:
        return live_catalog_names(self.policy_manager, self.registry)

    @asynccontextmanager
    async def _file_lock(self, policy_path: Path) -> AsyncIterator[None]:
        if fcntl is None:
            yield
            return

        lock_path = policy_path.with_suffix(policy_path.suffix + ".lock")
        deadline = time.monotonic() + self.file_lock_timeout_seconds

        def acquire() -> int:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fd
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        os.close(fd)
                        raise PolicyChangeError(
                            "policy_conflict",
                            "another writer holds the policy file lock; call policy_read and retry",
                        )
                    time.sleep(0.05)

        fd = await asyncio.to_thread(acquire)
        try:
            yield
        finally:

            def release() -> None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

            await asyncio.to_thread(release)

    # ── Public read-only API ────────────────────────────────────────────

    def read(self) -> PolicyReadResult:
        """Read the file from disk (not the active in-memory snapshot)."""
        path = self._policy_path()
        raw_bytes = path.read_bytes()
        file_hash = hash_policy_bytes(raw_bytes)
        document = PolicyDocument.from_yaml(raw_bytes.decode("utf-8"))
        policy = document.to_policy()

        unreachable, unverified = self._catalog_report(policy)
        identity = self.policy_manager.identity
        return PolicyReadResult(
            document=document,
            content_hash=identity.content_hash if identity is not None else None,
            file_hash=file_hash,
            path=path,
            writable=self.writable,
            unreachable_tools=unreachable,
            unverified_patterns=unverified,
        )

    def validate(self, document: PolicyDocument | None) -> PolicyValidationResult:
        """Dry-run structural and catalog validation. Never writes anything."""
        if document is None:
            document = self.read().document
        try:
            policy = document.to_policy()
            validate_policy_structure(policy)
        except PolicyContractError as exc:
            return PolicyValidationResult(
                ok=False, errors=(str(exc),), unreachable_tools=frozenset(), unverified_patterns={}
            )

        live_tools = self._live_names()
        snapshot = self.policy_manager.catalog_snapshot()
        result = validate_policy_against_catalog(
            policy,
            live_tools | snapshot.active,
            reserved_tool_names=snapshot.reserved,
            wip_tool_names=snapshot.wip,
        )
        errors, unverified = split_unverified_allow_patterns(
            policy, result.unmatched_allow_patterns, self.policy_manager.upstream_catalog_state()
        )
        return PolicyValidationResult(
            ok=not errors,
            errors=errors,
            unreachable_tools=result.unreachable_tools,
            unverified_patterns=unverified,
        )

    @property
    def writable(self) -> bool:
        """Whether :meth:`change`/``.rollback`` could succeed on file-access grounds.

        ``False`` whenever ``KEYSTONE_MCP_POLICY_TOOLS != "full"`` (including
        ``"read-only"``, independent of the file's actual permissions), or the
        policy file or its directory is not OS-writable.
        """
        if self.settings.policy_tools != "full":
            return False
        try:
            path = self._policy_path()
        except PolicyLoadError:
            return False
        return _is_writable(path)

    # ── Public write API ─────────────────────────────────────────────────

    async def change(
        self,
        *,
        changes: Sequence[PolicyChange],
        actor: str,
        actor_roles: frozenset[str],
        expected_hash: str | None,
        operation: str,
        task_id: str,
        actor_interactive: bool = True,
    ) -> PolicyChangeResult:
        """Apply ``changes`` to the policy file; see the module docstring for the steps."""
        version_before = self._safe_current_version()
        path = self._policy_path()
        self._assert_writable_or_raise(path)
        try:
            async with self._lock:
                async with self._file_lock(path):
                    result = await self._change_locked(
                        path=path,
                        changes=changes,
                        actor=actor,
                        actor_roles=actor_roles,
                        expected_hash=expected_hash,
                        operation=operation,
                        actor_interactive=actor_interactive,
                    )
        except _WriteFailed as exc:
            self._audit(
                operation=operation,
                actor=actor,
                outcome="error",
                code=exc.code,
                task_id=task_id,
                version_before=version_before,
                version_after=None,
                hash_before=None,
                hash_after=None,
                changes=changes,
                warnings_count=0,
            )
            raise
        except _ReloadFailedAfterWrite as exc:
            self._audit(
                operation=operation,
                actor=actor,
                outcome="error",
                code=exc.code,
                task_id=task_id,
                version_before=version_before,
                version_after=None,
                hash_before=None,
                hash_after=None,
                changes=changes,
                warnings_count=0,
            )
            raise
        except PolicyChangeError as exc:
            self._audit(
                operation=operation,
                actor=actor,
                outcome="refused",
                code=exc.code,
                task_id=task_id,
                version_before=version_before,
                version_after=None,
                hash_before=None,
                hash_after=None,
                changes=changes,
                warnings_count=0,
            )
            raise
        result = await self._publish_revision_after_write(result)
        self._audit(
            operation=operation,
            actor=actor,
            outcome="applied" if result.changed else "noop",
            code=None,
            task_id=task_id,
            version_before=version_before,
            version_after=result.document.version,
            hash_before=result.content_hash_before,
            hash_after=result.content_hash_after,
            changes=changes,
            warnings_count=len(result.warnings),
        )
        self._wake_surface_after_mutation(result)
        return result

    async def rollback(
        self,
        *,
        actor: str,
        actor_roles: frozenset[str],
        task_id: str,
        expected_hash: str | None = None,
        actor_interactive: bool = True,
    ) -> PolicyChangeResult:
        """Restore ``<policy>.bak`` over the current file (one generation deep)."""
        version_before = self._safe_current_version()
        path = self._policy_path()
        self._assert_writable_or_raise(path)
        try:
            async with self._lock:
                async with self._file_lock(path):
                    result = await self._rollback_locked(
                        path=path,
                        actor=actor,
                        actor_roles=actor_roles,
                        expected_hash=expected_hash,
                        actor_interactive=actor_interactive,
                    )
        except _WriteFailed as exc:
            self._audit(
                operation="policy_rollback",
                actor=actor,
                outcome="error",
                code=exc.code,
                task_id=task_id,
                version_before=version_before,
                version_after=None,
                hash_before=None,
                hash_after=None,
                changes=(),
                warnings_count=0,
            )
            raise
        except _ReloadFailedAfterWrite as exc:
            self._audit(
                operation="policy_rollback",
                actor=actor,
                outcome="error",
                code=exc.code,
                task_id=task_id,
                version_before=version_before,
                version_after=None,
                hash_before=None,
                hash_after=None,
                changes=(),
                warnings_count=0,
            )
            raise
        except PolicyChangeError as exc:
            self._audit(
                operation="policy_rollback",
                actor=actor,
                outcome="refused",
                code=exc.code,
                task_id=task_id,
                version_before=version_before,
                version_after=None,
                hash_before=None,
                hash_after=None,
                changes=(),
                warnings_count=0,
            )
            raise
        result = await self._publish_revision_after_write(result)
        self._audit(
            operation="policy_rollback",
            actor=actor,
            outcome="applied",
            code=None,
            task_id=task_id,
            version_before=version_before,
            version_after=result.document.version,
            hash_before=result.content_hash_before,
            hash_after=result.content_hash_after,
            changes=(),
            warnings_count=len(result.warnings),
        )
        self._wake_surface_after_mutation(result)
        return result

    def _wake_surface_after_mutation(self, result: PolicyChangeResult) -> None:
        if not (result.changed and result.reloaded):
            return
        mutator = self.surface_mutator
        if mutator is not None:
            mutator()

    async def _publish_revision_after_write(self, result: PolicyChangeResult) -> PolicyChangeResult:
        if not result.changed or not result.reloaded or self.revision_watcher is None:
            return result
        published = await self.revision_watcher.publish(result.content_hash_after)
        if published is not None:
            return result
        extra = (
            "other replicas were not notified (Redis unavailable); "
            "they pick the change up on their next refresh"
        )
        return replace(result, warnings=(*result.warnings, extra))

    def _safe_current_version(self) -> str | None:
        try:
            return self.read().document.version
        except Exception:
            return None

    # ── Write path internals ─────────────────────────────────────────────

    def _assert_writable_or_raise(self, path: Path) -> None:
        if self.settings.policy_tools != "full":
            raise PolicyChangeError(
                "policy_readonly",
                "policy tools are read-only on this instance (KEYSTONE_MCP_POLICY_TOOLS)",
            )
        if not _is_writable(path):
            raise PolicyChangeError(
                "policy_readonly",
                f"policy file is not writable: {path}; mount it read-write "
                "(see docs/policy-admin.md)",
            )

    async def _change_locked(
        self,
        *,
        path: Path,
        changes: Sequence[PolicyChange],
        actor: str,
        actor_roles: frozenset[str],
        expected_hash: str | None,
        operation: str,
        actor_interactive: bool = True,
    ) -> PolicyChangeResult:
        raw_bytes = await asyncio.to_thread(path.read_bytes)
        file_hash = hash_policy_bytes(raw_bytes)
        if expected_hash is not None and expected_hash != file_hash:
            raise PolicyChangeError(
                "policy_conflict",
                "policy file changed since it was read; call policy_read and retry",
            )
        document = PolicyDocument.from_yaml(raw_bytes.decode("utf-8"))
        before_policy = document.to_policy()

        candidate_document = document
        for change in changes:
            candidate_document = candidate_document.apply(change)

        if candidate_document == document:
            return PolicyChangeResult(
                changed=False,
                document=document,
                content_hash_before=file_hash,
                content_hash_after=file_hash,
                warnings=(),
            )

        candidate_policy, warnings = self._validate_candidate(candidate_document)
        self._check_invariants(candidate_policy, actor_roles, actor_interactive=actor_interactive)
        self._check_management_authority(
            before=before_policy,
            candidate=candidate_policy,
            actor_roles=actor_roles,
            operation=operation,
        )
        await check_full_administrator_remains(before_policy, candidate_policy, self.directory)
        for change in changes:
            if isinstance(change, RoleDelete):
                await check_role_in_use(change, self.directory)

        current_bytes = await asyncio.to_thread(path.read_bytes)
        if hash_policy_bytes(current_bytes) != file_hash:
            raise PolicyChangeError(
                "policy_conflict",
                "policy file changed while this change was being prepared; "
                "call policy_read and retry",
            )

        new_text = candidate_document.to_yaml(actor=actor, now=self._now())
        new_bytes = new_text.encode("utf-8")
        try:
            await asyncio.to_thread(_write_with_backup, path, new_bytes, backup=raw_bytes)
        except OSError as exc:
            raise _WriteFailed(f"policy file could not be written: {exc.strerror}") from exc

        try:
            reload_result = await asyncio.to_thread(self.policy_manager.reload, self.registry)
        except OSError as exc:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(_atomic_write, path, raw_bytes, mode_from=path)
            raise _WriteFailed(f"policy file could not be written: {exc.strerror}") from exc

        if not reload_result.success:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(_atomic_write, path, raw_bytes, mode_from=path)
            await asyncio.to_thread(self.policy_manager.reload, self.registry)
            raise _ReloadFailedAfterWrite(
                f"policy reload failed after write, backup restored: {reload_result.error}",
            )

        identity = self.policy_manager.identity
        content_hash_after = (
            identity.content_hash if identity is not None else hash_policy_bytes(new_bytes)
        )
        return PolicyChangeResult(
            changed=True,
            document=candidate_document,
            content_hash_before=file_hash,
            content_hash_after=content_hash_after,
            warnings=warnings,
            reloaded=True,
        )

    async def _rollback_locked(
        self,
        *,
        path: Path,
        actor: str,
        actor_roles: frozenset[str],
        expected_hash: str | None,
        actor_interactive: bool = True,
    ) -> PolicyChangeResult:
        bak_path = path.with_suffix(path.suffix + ".bak")
        if not bak_path.is_file():
            raise PolicyChangeError("nothing_to_rollback", "no backup to roll back to")

        current_bytes = await asyncio.to_thread(path.read_bytes)
        file_hash_before = hash_policy_bytes(current_bytes)
        if expected_hash is not None and expected_hash != file_hash_before:
            raise PolicyChangeError(
                "policy_conflict",
                "policy file changed since it was read; call policy_read and retry",
            )

        backup_bytes = await asyncio.to_thread(bak_path.read_bytes)
        current_document = PolicyDocument.from_yaml(current_bytes.decode("utf-8"))
        before_policy = current_document.to_policy()
        candidate_document = PolicyDocument.from_yaml(backup_bytes.decode("utf-8"))

        candidate_policy, warnings = self._validate_candidate(candidate_document)
        self._check_invariants(candidate_policy, actor_roles, actor_interactive=actor_interactive)
        self._check_management_authority(
            before=before_policy,
            candidate=candidate_policy,
            actor_roles=actor_roles,
            operation="policy_rollback",
        )
        await check_full_administrator_remains(before_policy, candidate_policy, self.directory)
        for role_name in sorted(set(current_document.roles) - set(candidate_document.roles)):
            await check_role_in_use(RoleDelete(role_name), self.directory)

        recheck = await asyncio.to_thread(path.read_bytes)
        if hash_policy_bytes(recheck) != file_hash_before:
            raise PolicyChangeError(
                "policy_conflict",
                "policy file changed while this change was being prepared; "
                "call policy_read and retry",
            )

        try:
            await asyncio.to_thread(_atomic_write, bak_path, current_bytes, mode_from=path)
            await asyncio.to_thread(_atomic_write, path, backup_bytes, mode_from=path)
        except OSError as exc:
            raise _WriteFailed(f"policy file could not be written: {exc.strerror}") from exc

        try:
            reload_result = await asyncio.to_thread(self.policy_manager.reload, self.registry)
        except OSError as exc:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(_atomic_write, path, current_bytes, mode_from=path)
                await asyncio.to_thread(_atomic_write, bak_path, backup_bytes, mode_from=path)
            raise _WriteFailed(f"policy file could not be written: {exc.strerror}") from exc

        if not reload_result.success:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(_atomic_write, path, current_bytes, mode_from=path)
                await asyncio.to_thread(_atomic_write, bak_path, backup_bytes, mode_from=path)
            await asyncio.to_thread(self.policy_manager.reload, self.registry)
            raise _ReloadFailedAfterWrite(
                "policy reload failed after rollback, previous file restored: "
                f"{reload_result.error}",
            )

        identity = self.policy_manager.identity
        content_hash_after = (
            identity.content_hash if identity is not None else hash_policy_bytes(backup_bytes)
        )
        return PolicyChangeResult(
            changed=True,
            document=candidate_document,
            content_hash_before=file_hash_before,
            content_hash_after=content_hash_after,
            warnings=warnings,
            reloaded=True,
        )

    # ── Shared validation ────────────────────────────────────────────────

    def _validate_candidate(self, document: PolicyDocument) -> tuple[RbacPolicy, tuple[str, ...]]:
        """Structural + live-catalog gate, the same one a hot-reload runs.

        Raises :class:`PolicyChangeError` (``policy_invalid`` or
        ``unmatched_pattern``) on failure; returns the validated policy plus
        non-fatal warning strings (unreachable tools, unverified patterns) on
        success.
        """
        try:
            candidate_policy = document.to_policy()
            validate_policy_structure(candidate_policy)
        except PolicyContractError as exc:
            raise PolicyChangeError("policy_invalid", str(exc)) from exc

        live_tools = self._live_names()
        snapshot = self.policy_manager.catalog_snapshot()
        upstream_state = self.policy_manager.upstream_catalog_state()
        try:
            assert_live_catalog_validation(
                candidate_policy,
                live_tools,
                catalog_snapshot=snapshot,
                upstream_state=upstream_state,
            )
        except PolicyContractError as exc:
            raise PolicyChangeError("unmatched_pattern", str(exc)) from exc

        unreachable, unverified = self._catalog_report(candidate_policy)
        warnings = [f"unreachable: {name}" for name in sorted(unreachable)]
        for namespace, entries in sorted(unverified.items()):
            warnings.append(f"not verified ({namespace}): {', '.join(entries)}")
        return candidate_policy, tuple(warnings)

    def _check_invariants(
        self,
        candidate_policy: RbacPolicy,
        actor_roles: frozenset[str],
        *,
        actor_interactive: bool = True,
    ) -> None:
        live_tools = self._live_names()
        check_no_role_can_administer(
            candidate_policy,
            live_tools,
            interactive_login_available=self.interactive_login_available,
        )
        check_self_lockout_forbidden(
            candidate_policy,
            actor_roles,
            live_tools,
            actor_interactive=actor_interactive,
        )

    def _check_management_authority(
        self,
        *,
        before: RbacPolicy,
        candidate: RbacPolicy,
        actor_roles: frozenset[str],
        operation: str,
    ) -> None:
        reasons = management_change_reasons(before, candidate)
        if not reasons:
            return
        snapshot_policy = self.policy_manager.active_policy
        if snapshot_policy is None:
            view = ManagementView((before,))
        else:
            view = ManagementView((snapshot_policy, before))
        if view.is_full_administrator(actor_roles):
            return
        if self.observability is not None:
            self.observability.record_admin_refusal(operation=operation, reason="management_role")
        raise PolicyChangeError(
            "forbidden",
            "only a full administrator can make this change: " + "; ".join(reasons),
        )

    def _catalog_report(
        self, policy: RbacPolicy
    ) -> tuple[frozenset[str], dict[str, tuple[str, ...]]]:
        """Non-fatal catalog findings: unreachable tools, not-yet-verified patterns."""
        live_tools = self._live_names()
        snapshot = self.policy_manager.catalog_snapshot()
        result = validate_policy_against_catalog(
            policy,
            live_tools | snapshot.active,
            reserved_tool_names=snapshot.reserved,
            wip_tool_names=snapshot.wip,
        )
        _errors, unverified = split_unverified_allow_patterns(
            policy, result.unmatched_allow_patterns, self.policy_manager.upstream_catalog_state()
        )
        return result.unreachable_tools, unverified

    # ── Plumbing ─────────────────────────────────────────────────────────

    def _policy_path(self) -> Path:
        return self.policy_manager.policy_path()

    def _now(self) -> datetime:
        return self.clock()

    def _audit(
        self,
        *,
        operation: str,
        actor: str,
        outcome: str,
        code: str | None,
        task_id: str,
        version_before: str | None,
        version_after: str | None,
        hash_before: str | None,
        hash_after: str | None,
        changes: Sequence[PolicyChange],
        warnings_count: int,
    ) -> None:
        if self.observability is None:
            return
        try:
            self.observability.record_policy_mutation(
                operation=operation,
                actor_email=actor,
                outcome=outcome,
                code=code,
                task_id=task_id,
                policy_version_before=version_before,
                policy_version_after=version_after,
                content_hash_before=hash_before,
                content_hash_after=hash_after,
                changes=describe_changes(list(changes)),
                warnings_count=warnings_count,
            )
        except Exception:  # pragma: no cover - audit must never break a mutation
            logger.warning("rbac policy mutation observability failed", exc_info=True)


def _is_writable(path: Path) -> bool:
    return os.access(path, os.W_OK) and os.access(path.parent, os.W_OK)
