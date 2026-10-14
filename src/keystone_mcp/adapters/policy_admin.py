"""Builtin policy_* admin tools over :class:`~keystone_mcp.rbac.policy_store.PolicyStore`."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import yaml

from keystone_mcp.adapters.guards import require_human_actor
from keystone_mcp.rbac.human_identity import has_interactive_human_identity
from keystone_mcp.rbac.loader import PolicyLoadError, live_catalog_names
from keystone_mcp.rbac.policy import PolicyContractError
from keystone_mcp.rbac.policy_document import (
    LIST_FIELD_NAMES,
    AllowAdd,
    AllowRemove,
    ListSet,
    PolicyChangeError,
    PolicyDocument,
    RoleDelete,
    RoleSet,
)
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.rbac.upstream_state import pattern_owner
from keystone_mcp.user_directory.critical import is_critical_tool
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route
    from keystone_mcp.user_directory.protocol import UserDirectory

_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_MUTATION_TOOLS = frozenset(
    {
        "policy_role_set",
        "policy_role_delete",
        "policy_allow_add",
        "policy_allow_remove",
        "policy_list_set",
        "policy_rollback",
    }
)

#: Stable ``code`` values :class:`PolicyAdminAdapter` may return (V02 contract).
POLICY_ADMIN_ERROR_CODES: frozenset[str] = frozenset(
    {
        "forbidden",
        "nothing_to_rollback",
        "policy_conflict",
        "policy_invalid",
        "policy_invariant",
        "policy_readonly",
        "role_in_use",
        "role_not_found",
        "self_lockout_forbidden",
        "service_unavailable",
        "unmatched_pattern",
        "validation_error",
    }
)


class PolicyAdminAdapter:
    """Dispatches ``policy_*`` tool calls to a ``PolicyStore``."""

    def __init__(
        self,
        *,
        store: PolicyStore,
        directory: UserDirectory | None = None,
        observability: RbacObservability | None = None,
    ) -> None:
        self._store = store
        self._directory = directory
        self._observability = observability

    @staticmethod
    def _error(
        route: Route,
        ctx: RouteContext,
        *,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        return {
            "state": "error",
            "tool": route.name,
            "task_id": ctx.task_id,
            "code": code,
            "message": message,
        }

    @staticmethod
    def _done(route: Route, ctx: RouteContext, **payload: Any) -> dict[str, Any]:
        return {
            "state": "done",
            "tool": route.name,
            "task_id": ctx.task_id,
            **payload,
        }

    async def execute(
        self,
        route: Route,
        ctx: RouteContext,
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any]:
        spec = dict(request) if isinstance(request, dict) else dict(args)
        name = route.name

        if name in _MUTATION_TOOLS:
            refusal = require_human_actor(
                route,
                ctx,
                observability=self._observability,
                message="policy changes require a human administrator",
            )
            if refusal is not None:
                self._record_refusal(route, ctx, code=str(refusal["code"]))
                return refusal

        validation_error = self._validate_args(route, ctx, spec)
        if validation_error is not None:
            if name in _MUTATION_TOOLS:
                self._record_refusal(route, ctx, code=str(validation_error["code"]))
            return validation_error

        if isinstance(spec.get("role"), str):
            spec["role"] = spec["role"].strip()
        if name == "policy_list_set" and isinstance(spec.get("list"), str):
            spec["list"] = spec["list"].strip()

        if name in _MUTATION_TOOLS:
            actor_roles, roles_error = await self._actor_roles(route, ctx)
            if roles_error is not None:
                self._record_refusal(route, ctx, code=str(roles_error["code"]))
                return roles_error
            actor_interactive = has_interactive_human_identity(ctx.verified_identity)
        else:
            actor_roles = frozenset()
            actor_interactive = True

        actor = ctx.verified_identity.subject
        if ctx.verified_identity.email is not None:
            actor = normalize_email(actor)

        try:
            if name == "policy_read":
                result = self._store.read()
                policy_payload = _serialize_policy(result.document)
                bak_path = result.path.with_suffix(result.path.suffix + ".bak")
                return self._done(
                    route,
                    ctx,
                    policy=policy_payload,
                    content_hash=result.content_hash,
                    file_hash=result.file_hash,
                    path=str(result.path),
                    writable=result.writable,
                    mode=self._store.settings.policy_tools,
                    unreachable_tools=sorted(result.unreachable_tools),
                    unverified_patterns={
                        ns: list(entries) for ns, entries in result.unverified_patterns.items()
                    },
                    backup_available=bak_path.is_file(),
                )
            if name == "policy_catalog":
                return self._done(
                    route,
                    ctx,
                    **_catalog_payload(
                        self._store,
                        namespace=spec.get("namespace"),
                        role=spec.get("role"),
                    ),
                )
            if name == "policy_validate":
                document, parse_error = _document_from_optional_policy(spec.get("policy"))
                if parse_error is not None:
                    return self._error(route, ctx, code=parse_error[0], message=parse_error[1])
                validation = self._store.validate(document)
                return self._done(
                    route,
                    ctx,
                    ok=validation.ok,
                    errors=_format_validation_errors(validation.errors),
                    unmatched_allow_patterns=_unmatched_patterns(validation.errors),
                    unreachable_tools=sorted(validation.unreachable_tools),
                    unverified_patterns={
                        ns: list(entries) for ns, entries in validation.unverified_patterns.items()
                    },
                )
            if name == "policy_role_set":
                result = await self._store.change(
                    changes=[
                        RoleSet(
                            role=str(spec["role"]),
                            allow=spec["allow"],
                            description=str(spec.get("description") or ""),
                        )
                    ],
                    actor=actor,
                    actor_roles=actor_roles,
                    expected_hash=spec.get("expected_hash"),
                    operation=name,
                    task_id=ctx.task_id,
                    actor_interactive=actor_interactive,
                )
                role_name = str(spec["role"])
                body = result.document.roles[role_name]
                return self._done(
                    route,
                    ctx,
                    changed=result.changed,
                    role={
                        "name": role_name,
                        "description": body.description,
                        "allow": list(body.allow),
                    },
                    content_hash=result.content_hash_after,
                    warnings=list(result.warnings),
                )
            if name == "policy_role_delete":
                result = await self._store.change(
                    changes=[RoleDelete(str(spec["role"]))],
                    actor=actor,
                    actor_roles=actor_roles,
                    expected_hash=spec.get("expected_hash"),
                    operation=name,
                    task_id=ctx.task_id,
                    actor_interactive=actor_interactive,
                )
                return self._done(
                    route,
                    ctx,
                    changed=result.changed,
                    content_hash=result.content_hash_after,
                )
            if name == "policy_allow_add":
                result = await self._store.change(
                    changes=[AllowAdd(str(spec["role"]), spec["patterns"])],
                    actor=actor,
                    actor_roles=actor_roles,
                    expected_hash=spec.get("expected_hash"),
                    operation=name,
                    task_id=ctx.task_id,
                    actor_interactive=actor_interactive,
                )
                role_name = str(spec["role"])
                body = result.document.roles[role_name]
                added = [p for p in spec["patterns"] if p in body.allow]
                return self._done(
                    route,
                    ctx,
                    changed=result.changed,
                    role={
                        "name": role_name,
                        "description": body.description,
                        "allow": list(body.allow),
                    },
                    added=added,
                    content_hash=result.content_hash_after,
                    warnings=list(result.warnings),
                )
            if name == "policy_allow_remove":
                result = await self._store.change(
                    changes=[AllowRemove(str(spec["role"]), spec["patterns"])],
                    actor=actor,
                    actor_roles=actor_roles,
                    expected_hash=spec.get("expected_hash"),
                    operation=name,
                    task_id=ctx.task_id,
                    actor_interactive=actor_interactive,
                )
                role_name = str(spec["role"])
                body = result.document.roles[role_name]
                removed = [p for p in spec["patterns"] if p not in body.allow]
                return self._done(
                    route,
                    ctx,
                    changed=result.changed,
                    role={
                        "name": role_name,
                        "description": body.description,
                        "allow": list(body.allow),
                    },
                    removed=removed,
                    content_hash=result.content_hash_after,
                    warnings=list(result.warnings),
                )
            if name == "policy_list_set":
                result = await self._store.change(
                    changes=[ListSet(str(spec["list"]), spec["patterns"])],
                    actor=actor,
                    actor_roles=actor_roles,
                    expected_hash=spec.get("expected_hash"),
                    operation=name,
                    task_id=ctx.task_id,
                    actor_interactive=actor_interactive,
                )
                list_name = str(spec["list"])
                patterns = list(getattr(result.document, list_name))
                return self._done(
                    route,
                    ctx,
                    changed=result.changed,
                    list=list_name,
                    patterns=patterns,
                    content_hash=result.content_hash_after,
                    warnings=list(result.warnings),
                )
            assert name == "policy_rollback"
            result = await self._store.rollback(
                actor=actor,
                actor_roles=actor_roles,
                task_id=ctx.task_id,
                expected_hash=spec.get("expected_hash"),
                actor_interactive=actor_interactive,
            )
            return self._done(
                route,
                ctx,
                changed=result.changed,
                content_hash=result.content_hash_after,
                restored_version=result.document.version,
            )
        except PolicyChangeError as exc:
            message = exc.message
            if exc.code == "unmatched_pattern" and "policy_catalog" not in message:
                message = f"{message}; call policy_catalog to see published names"
            return self._error(route, ctx, code=exc.code, message=message)
        except (PolicyLoadError, PolicyContractError) as exc:
            return self._error(route, ctx, code="policy_invalid", message=str(exc))

    def _record_refusal(self, route: Route, ctx: RouteContext, *, code: str) -> None:
        if self._observability is None:
            return
        self._observability.record_policy_mutation(
            operation=route.name,
            actor_email=ctx.verified_identity.subject,
            outcome="refused",
            code=code,
            task_id=ctx.task_id,
            actor_subject_type=ctx.verified_identity.subject_type,
        )

    async def _actor_roles(
        self, route: Route, ctx: RouteContext
    ) -> tuple[frozenset[str], dict[str, Any] | None]:
        directory = self._directory
        if directory is None:
            return frozenset(), self._error(
                route,
                ctx,
                code="service_unavailable",
                message="user directory is not configured; cannot verify administrator roles",
            )
        actor = ctx.verified_identity.subject
        if ctx.verified_identity.email is not None:
            actor = normalize_email(actor)
        try:
            resolved = await directory.resolve_user(actor)
        except Exception as exc:  # noqa: BLE001
            return frozenset(), self._error(
                route,
                ctx,
                code="service_unavailable",
                message=str(exc),
            )
        return frozenset(resolved.roles), None

    def _validate_args(
        self, route: Route, ctx: RouteContext, spec: dict[str, Any]
    ) -> dict[str, Any] | None:
        name = route.name

        def err(message: str) -> dict[str, Any]:
            return self._error(route, ctx, code="validation_error", message=message)

        if name == "policy_role_set":
            role_error = _require_role(spec.get("role"), err)
            if role_error is not None:
                return role_error
            allow_error = _require_pattern_list(spec.get("allow"), "allow", err)
            if isinstance(allow_error, dict):
                return allow_error
            return _validate_expected_hash(spec.get("expected_hash"), err)

        if name == "policy_role_delete":
            role_error = _require_role(spec.get("role"), err)
            if role_error is not None:
                return role_error
            return _validate_expected_hash(spec.get("expected_hash"), err)

        if name in ("policy_allow_add", "policy_allow_remove"):
            role_error = _require_role(spec.get("role"), err)
            if role_error is not None:
                return role_error
            patterns_error = _require_pattern_list(spec.get("patterns"), "patterns", err)
            if isinstance(patterns_error, dict):
                return patterns_error
            return _validate_expected_hash(spec.get("expected_hash"), err)

        if name == "policy_list_set":
            list_name = spec.get("list")
            if not isinstance(list_name, str) or not list_name.strip():
                return err("list is required")
            list_name = list_name.strip()
            if list_name not in LIST_FIELD_NAMES:
                expected = ", ".join(sorted(LIST_FIELD_NAMES))
                return err(f"unknown list {list_name!r}; expected one of: {expected}")
            patterns_error = _require_pattern_list(spec.get("patterns"), "patterns", err)
            if isinstance(patterns_error, dict):
                return patterns_error
            return _validate_expected_hash(spec.get("expected_hash"), err)

        if name in _MUTATION_TOOLS:
            return _validate_expected_hash(spec.get("expected_hash"), err)

        if name == "policy_validate" and spec.get("policy") is not None:
            if not isinstance(spec.get("policy"), dict):
                return err("policy must be a mapping when provided")

        if name == "policy_catalog":
            for key in ("namespace", "role"):
                value = spec.get(key)
                if value is not None and (not isinstance(value, str) or not value.strip()):
                    return err(f"{key} must be a non-empty string when provided")

        return None


def _serialize_policy(document: PolicyDocument) -> dict[str, Any]:
    return {
        "version": document.version,
        "roles": {
            name: {
                "description": body.description,
                "allow": list(body.allow),
            }
            for name, body in sorted(document.roles.items())
        },
        "deny": list(document.deny),
        "requires_human_identity": list(document.requires_human_identity),
        "critical_tools": list(document.critical_tools),
        "reserved_allow_patterns": list(document.reserved_allow_patterns),
    }


def _document_from_optional_policy(
    raw: Any,
) -> tuple[PolicyDocument | None, tuple[str, str] | None]:
    if raw is None:
        return None, None
    if not isinstance(raw, dict):
        return None, ("validation_error", "policy must be a mapping when provided")
    try:
        return PolicyDocument.from_yaml(yaml.safe_dump(raw, sort_keys=False)), None
    except PolicyContractError as exc:
        return None, ("policy_invalid", str(exc))


def _require_role(role: Any, err: Any) -> dict[str, Any] | None:
    if not isinstance(role, str) or not role.strip():
        return err("role must be a non-empty string")
    return None


def _require_pattern_list(patterns: Any, field: str, err: Any) -> list[str] | dict[str, Any]:
    if not isinstance(patterns, list) or not patterns:
        return err(f"{field} must be a non-empty list of patterns")
    cleaned: list[str] = []
    for item in patterns:
        if not isinstance(item, str) or not item.strip():
            return err(f"{field} must be a non-empty list of patterns")
        if any(ch.isspace() for ch in item):
            return err(f"pattern {item!r} contains whitespace")
        cleaned.append(item.strip())
    return cleaned


def _validate_expected_hash(value: Any, err: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _HEX_HASH_RE.match(value):
        return err("expected_hash must be a 64-character hexadecimal string")
    return None


def _format_validation_errors(errors: tuple[str, ...]) -> list[dict[str, str]]:
    formatted: list[dict[str, str]] = []
    for item in errors:
        if ":" in item and not item.startswith("unknown"):
            formatted.append(
                {
                    "code": "unmatched_pattern",
                    "message": (
                        f"unmatched allow pattern {item}; "
                        "call policy_catalog to see published names"
                    ),
                }
            )
        else:
            formatted.append({"code": "policy_invalid", "message": item})
    return formatted


def _unmatched_patterns(errors: tuple[str, ...]) -> list[str]:
    patterns: list[str] = []
    for item in errors:
        if ":" in item:
            _, pattern = item.split(":", 1)
            patterns.append(pattern)
    return patterns


def _tool_namespace(tool_name: str, namespaces: frozenset[str]) -> str:
    owner = pattern_owner(tool_name, namespaces)
    if owner is not None:
        return owner
    if "_" in tool_name:
        return tool_name.split("_", 1)[0]
    return tool_name


def _catalog_payload(
    store: PolicyStore,
    *,
    namespace: str | None,
    role: str | None,
) -> dict[str, Any]:
    manager = store.policy_manager
    policy = manager.policy
    if policy is None:
        raise PolicyLoadError("no active RBAC policy loaded")

    live_names = live_catalog_names(store.policy_manager, store.registry)
    snapshot = manager.catalog_snapshot()
    state = manager.upstream_catalog_state()
    namespaces = state.namespaces if state is not None else frozenset()

    sources: dict[str, str] = {}
    for name in live_names:
        sources[name] = "live"
    for name in sorted(snapshot.active):
        sources.setdefault(name, "snapshot_active")
    for name in sorted(snapshot.reserved):
        sources.setdefault(name, "snapshot_reserved")
    for name in sorted(snapshot.wip):
        sources.setdefault(name, "snapshot_wip")

    namespace_filter = namespace.strip() if isinstance(namespace, str) else None
    role_filter = role.strip() if isinstance(role, str) else None

    tools: list[dict[str, Any]] = []
    critical_patterns = policy.critical_tool_patterns
    for tool_name in sorted(sources):
        tool_ns = _tool_namespace(tool_name, namespaces)
        if namespace_filter is not None and tool_ns != namespace_filter:
            continue
        if role_filter is not None and not policy.allows_role(role_filter, tool_name):
            continue
        roles_allowed = sorted(r for r in policy.role_names if policy.allows_role(r, tool_name))
        tools.append(
            {
                "name": tool_name,
                "namespace": tool_ns,
                "roles": roles_allowed,
                "critical": is_critical_tool(tool_name, critical_patterns),
                "requires_human": policy.requires_human_identity(tool_name),
                "denied": policy.is_globally_denied(tool_name),
                "source": sources[tool_name],
            }
        )
    return {"tools": tools, "total": len(tools)}
