"""Readiness probe backing ``GET /readyz``.

``/healthz`` answers "is the process alive" and never fails: a process that
cannot reach Redis or load its RBAC policy is still listening and would
answer ``/healthz`` with 200, so a load balancer or orchestrator keeps
sending it traffic that cannot possibly succeed. ``/readyz`` answers "can
this replica serve work right now" by checking the dependencies without
which every login or RBAC-gated call fails anyway.

Checks run in parallel, each under its own short timeout, so one slow
dependency does not make the others wait and a poll never blocks longer than
``timeout_seconds``. The users directory's HTTP backend (used when forks
point at an external directory service) is deliberately not checked here:
that service's own availability already fails closed on every call that
needs it (see :class:`~keystone_mcp.user_directory.http.HttpUserDirectoryBackend`),
and treating its outage as "this Keystone replica is not ready" would pull
every replica out of rotation at once over a problem no restart or redeploy
of Keystone fixes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.router.upstream import UpstreamRegistry

logger = logging.getLogger(__name__)

CheckResult = Literal["ok", "fail", "skipped", "pending"]

DEFAULT_TIMEOUT_SECONDS = 1.0

_CHECK_NAMES = ("redis", "rbac_policy", "users_directory", "bootstrap")


class BootstrapState:
    """Deferred HTTP startup: upstream discovery and policy load after the port opens."""

    __slots__ = ("_failure_reason", "_status")

    def __init__(self, *, deferred: bool = False) -> None:
        self._status: Literal["pending", "ready", "failed"] = "pending" if deferred else "ready"
        self._failure_reason: str | None = None

    @property
    def status(self) -> Literal["pending", "ready", "failed"]:
        return self._status

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    def is_pending(self) -> bool:
        return self._status == "pending"

    def mark_ready(self) -> None:
        self._status = "ready"
        self._failure_reason = None

    def mark_failed(self, reason: str) -> None:
        self._status = "failed"
        self._failure_reason = reason


@dataclass(frozen=True)
class ReadinessReport:
    """Outcome of one :meth:`ReadinessProbe.run` poll."""

    ready: bool
    checks: dict[str, CheckResult]


class ReadinessProbe:
    """Polls Redis, the active RBAC policy, and the users directory backend.

    One instance is built per server process (see ``server.py``) and reused
    for every ``/readyz`` poll, so transitions between ready and degraded are
    logged once rather than on every poll a load balancer sends.
    """

    def __init__(
        self,
        *,
        redis: Redis | None,
        policy_manager: RbacPolicyManager | None,
        users_backend: object | None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        upstreams: UpstreamRegistry | None = None,
        require_all: bool = False,
        bootstrap_state: BootstrapState | None = None,
    ) -> None:
        self._redis = redis
        self._policy_manager = policy_manager
        self._users_backend = users_backend
        self._timeout_seconds = timeout_seconds
        self._upstreams = upstreams
        self._require_all = require_all
        self._bootstrap_state = bootstrap_state
        # None until the first poll completes, so the very first result never
        # logs a "restored" transition it did not earn.
        self._was_ready: bool | None = None

    async def run(self) -> ReadinessReport:
        (
            (redis_result, redis_exc),
            (rbac_result, rbac_exc),
            (users_result, users_exc),
            (bootstrap_result, bootstrap_exc),
        ) = await asyncio.gather(
            self._check_redis(),
            self._check_rbac_policy(),
            self._check_users_directory(),
            self._check_bootstrap(),
        )
        checks: dict[str, CheckResult] = {
            "redis": redis_result,
            "rbac_policy": rbac_result,
            "users_directory": users_result,
            "bootstrap": bootstrap_result,
        }
        if self._require_all and self._upstreams is not None:
            unavailable = self._upstreams.unavailable_namespaces()
            checks["upstreams"] = "fail" if unavailable else "ok"
        exceptions = {
            "redis": redis_exc,
            "rbac_policy": rbac_exc,
            "users_directory": users_exc,
            "bootstrap": bootstrap_exc,
        }
        ready = all(value in ("ok", "skipped") for value in checks.values())
        self._log_transition(ready, checks, exceptions)
        return ReadinessReport(ready=ready, checks=checks)

    async def _check_bootstrap(self) -> tuple[CheckResult, str | None]:
        state = self._bootstrap_state
        if state is None or state.status == "ready":
            return "ok", None
        if state.status == "pending":
            return "pending", "BootstrapPending"
        return "fail", state.failure_reason or "BootstrapFailed"

    async def _check_redis(self) -> tuple[CheckResult, str | None]:
        if self._redis is None:
            return "skipped", None
        try:
            await asyncio.wait_for(self._redis.ping(), timeout=self._timeout_seconds)
        except Exception as exc:
            return "fail", type(exc).__name__
        return "ok", None

    async def _check_rbac_policy(self) -> tuple[CheckResult, str | None]:
        if self._policy_manager is None:
            return "skipped", None
        try:
            active = self._policy_manager.active_policy
        except Exception as exc:
            return "fail", type(exc).__name__
        if active is not None:
            return "ok", None
        # No exception here -- this is an absence, not a failure -- so the
        # log line still names the reason rather than printing "unknown".
        return "fail", "NoActivePolicy"

    async def _check_users_directory(self) -> tuple[CheckResult, str | None]:
        backend = self._users_backend
        ping = getattr(backend, "ping", None)
        if backend is None or ping is None:
            # No backend wired (RBAC and Google login both off), or the
            # HTTP backend (no ping method by design -- see module docstring).
            return "skipped", None
        try:
            await asyncio.wait_for(ping(), timeout=self._timeout_seconds)
        except Exception as exc:
            return "fail", type(exc).__name__
        return "ok", None

    def _log_transition(
        self,
        ready: bool,
        checks: dict[str, CheckResult],
        exceptions: dict[str, str | None],
    ) -> None:
        if ready:
            if self._was_ready is False:
                logger.info("readiness restored")
            self._was_ready = True
            return
        if self._was_ready is not False:
            for name in _CHECK_NAMES:
                value = checks.get(name)
                if value == "fail":
                    logger.warning(
                        "readiness degraded: %s=fail (%s)",
                        name,
                        exceptions.get(name) or "Unknown",
                    )
                elif value == "pending" and name == "bootstrap":
                    logger.warning(
                        "readiness degraded: bootstrap=pending (BootstrapPending)",
                    )
        self._was_ready = False
