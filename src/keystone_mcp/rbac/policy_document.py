"""Mutable policy document: the writable counterpart of the frozen ``RbacPolicy``.

``RbacPolicy`` (``keystone_mcp.rbac.policy``) is the validated, in-memory,
read-only contract the router enforces against. ``PolicyDocument`` is the
editable model of the *file* on disk: it round-trips through YAML, applies one
``PolicyChange`` at a time (each returning a new, independently-validated
copy), and renders back to YAML deterministically so two writes of the same
content produce the same bytes (save for the header's timestamp).

Hand-written comments in the policy file are never preserved by a tool write:
PyYAML has no concept of them, and ``ruamel.yaml`` is deliberately not a
dependency here (see ``docs/rbac-policy-format.md``, "Tool writes"). The
original file survives as the single ``.bak`` generation
:class:`~keystone_mcp.rbac.policy_store.PolicyStore` keeps.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import yaml

from keystone_mcp.rbac.policy import (
    POLICY_TOP_LEVEL_KEYS,
    PolicyContractError,
    RbacPolicy,
    parse_policy_yaml,
)

#: A role name a tool may create: starts with a letter or digit, then up to 63
#: letters/digits/``_``/``-``. Chosen to be a safe YAML mapping key and a safe
#: fragment of an audit "changes" description, independent of what the
#: current file happens to contain already.
_ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

#: ``PolicyChange.name`` values :class:`ListSet` accepts.
LIST_FIELD_NAMES: frozenset[str] = frozenset(
    {"deny", "requires_human_identity", "critical_tools", "reserved_allow_patterns"}
)

_HEADER_TEMPLATE = (
    "# Managed by keystone-mcp policy tools (last change {timestamp} by {actor}).\n"
    "# Hand-written comments are not preserved by tool writes; see docs/policy-admin.md.\n"
)


class PolicyChangeError(Exception):
    """Raised when a :class:`PolicyChange` cannot be applied to a document.

    ``code`` is one of the stable error codes the ``policy_*`` tools (V02)
    promise their callers: ``role_not_found`` or ``validation_error`` from
    this module; ``policy_invariant``, ``self_lockout_forbidden``,
    ``role_in_use`` and ``service_unavailable`` from
    :mod:`keystone_mcp.rbac.policy_invariants`; ``policy_readonly``,
    ``policy_conflict``, ``policy_invalid``, ``unmatched_pattern`` and
    ``nothing_to_rollback`` from :mod:`keystone_mcp.rbac.policy_store`.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class RoleBody:
    """One role's editable body: free-text description plus allow patterns."""

    description: str
    allow: list[str]


@dataclass
class PolicyDocument:
    """Editable model of a policy YAML file (``default_deny`` is always ``true``)."""

    version: str
    roles: dict[str, RoleBody]
    deny: list[str] = field(default_factory=list)
    requires_human_identity: list[str] = field(default_factory=list)
    critical_tools: list[str] = field(default_factory=list)
    reserved_allow_patterns: list[str] = field(default_factory=list)
    tool_dispositions: dict[str, list[str]] = field(default_factory=dict)

    # ── Parsing ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, raw: str) -> PolicyDocument:
        """Parse policy YAML text into an editable document.

        Uses the same top-level key set and per-section shape as
        :func:`keystone_mcp.rbac.policy.parse_policy_yaml`, so a file this
        rejects is also rejected by the hot-reload path, and vice versa.
        """
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise PolicyContractError(f"invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyContractError("policy root must be a mapping")
        unknown = sorted(set(map(str, data)) - POLICY_TOP_LEVEL_KEYS)
        if unknown:
            raise PolicyContractError(
                "unknown top-level keys in policy: "
                + ", ".join(unknown)
                + f" (allowed: {', '.join(sorted(POLICY_TOP_LEVEL_KEYS))})"
            )

        version = str(data.get("version", "")).strip()
        roles_raw = data.get("roles")
        if not isinstance(roles_raw, dict):
            raise PolicyContractError("roles must be a mapping")

        roles: dict[str, RoleBody] = {}
        for name, body in roles_raw.items():
            if not isinstance(body, dict):
                raise PolicyContractError(f"role {name!r} must be a mapping")
            allow_raw = body.get("allow")
            if not isinstance(allow_raw, list) or not allow_raw:
                raise PolicyContractError(f"role {name!r}.allow must be a non-empty list")
            roles[str(name).strip()] = RoleBody(
                description=str(body.get("description", "")).strip(),
                allow=[str(item).strip() for item in allow_raw],
            )

        return cls(
            version=version,
            roles=roles,
            deny=_string_list(data.get("deny"), "deny"),
            requires_human_identity=_string_list(
                data.get("requires_human_identity"), "requires_human_identity"
            ),
            critical_tools=_string_list(data.get("critical_tools"), "critical_tools"),
            reserved_allow_patterns=_string_list(
                data.get("reserved_allow_patterns"), "reserved_allow_patterns"
            ),
            tool_dispositions=_dispositions_dict(data.get("tool_dispositions")),
        )

    # ── Rendering ────────────────────────────────────────────────────────

    def to_yaml(self, *, actor: str = "unknown", now: datetime | None = None) -> str:
        """Render back to YAML, deterministically but for the header's timestamp.

        Key order is :data:`~keystone_mcp.rbac.policy.POLICY_TOP_LEVEL_KEYS`'s
        order; roles are sorted by name; every optional section is always
        present (empty list/mapping when unset) so two renders of equivalent
        content differ only in the header's ``last change`` line.
        """
        timestamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
        header = _HEADER_TEMPLATE.format(timestamp=timestamp, actor=actor)
        data: dict[str, Any] = {
            "version": self.version,
            "default_deny": True,
            "roles": {
                name: {
                    "description": self.roles[name].description,
                    "allow": list(self.roles[name].allow),
                }
                for name in sorted(self.roles)
            },
            "deny": list(self.deny),
            "requires_human_identity": list(self.requires_human_identity),
            "critical_tools": list(self.critical_tools),
            "reserved_allow_patterns": list(self.reserved_allow_patterns),
            "tool_dispositions": {
                label: list(patterns) for label, patterns in self.tool_dispositions.items()
            },
        }
        body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
        return header + "\n" + body

    def to_policy(self) -> RbacPolicy:
        """Build the frozen, validated contract — through the same parser as any file."""
        return parse_policy_yaml(self.to_yaml())

    # ── Changes ──────────────────────────────────────────────────────────

    def apply(self, change: PolicyChange) -> PolicyDocument:
        """Return a new document with ``change`` applied; ``self`` is untouched.

        A change that has no effect (adding a pattern already present,
        removing one already absent) returns a document equal to ``self`` --
        not an error. See :class:`PolicyChangeError` for the error codes this
        can raise.
        """
        doc = copy.deepcopy(self)
        if isinstance(change, RoleSet):
            _apply_role_set(doc, change)
        elif isinstance(change, RoleDelete):
            _apply_role_delete(doc, change)
        elif isinstance(change, AllowAdd):
            _apply_allow_add(doc, change)
        elif isinstance(change, AllowRemove):
            _apply_allow_remove(doc, change)
        elif isinstance(change, ListSet):
            _apply_list_set(doc, change)
        elif isinstance(change, VersionSet):
            _apply_version_set(doc, change)
        else:  # pragma: no cover - defensive, PolicyChange is a closed union
            raise TypeError(f"unknown PolicyChange: {change!r}")
        return doc


# ── PolicyChange union ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RoleSet:
    """Create a role, or replace an existing one entirely."""

    role: str
    allow: list[str] | tuple[str, ...]
    description: str = ""


@dataclass(frozen=True, slots=True)
class RoleDelete:
    """Delete a role (refused by invariants while it is still assigned to anyone)."""

    role: str


@dataclass(frozen=True, slots=True)
class AllowAdd:
    """Add one or more allow patterns to an existing role (union, no duplicates)."""

    role: str
    patterns: list[str] | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AllowRemove:
    """Remove one or more allow patterns from an existing role.

    Refused with ``validation_error`` when it would leave the role with no
    allow patterns at all -- delete the role instead.
    """

    role: str
    patterns: list[str] | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ListSet:
    """Replace one global list section wholesale.

    ``name`` is one of :data:`LIST_FIELD_NAMES`.
    """

    name: str
    patterns: list[str] | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VersionSet:
    """Set the policy document's free-form ``version`` string."""

    version: str


PolicyChange = RoleSet | RoleDelete | AllowAdd | AllowRemove | ListSet | VersionSet


def describe_change(change: PolicyChange) -> str:
    """Short, pattern-free description for the audit trail's ``changes`` list.

    Never includes the pattern text itself (only counts) -- the audit record
    promises not to leak allow-pattern contents (see ``rbac_policy_mutation``
    in ``docs/observability-rbac.md``).
    """
    if isinstance(change, RoleSet):
        return f"role_set:{change.role}"
    if isinstance(change, RoleDelete):
        return f"role_delete:{change.role}"
    if isinstance(change, AllowAdd):
        return f"allow_add:{change.role}:+{len(change.patterns)}"
    if isinstance(change, AllowRemove):
        return f"allow_remove:{change.role}:-{len(change.patterns)}"
    if isinstance(change, ListSet):
        return f"list_set:{change.name}"
    if isinstance(change, VersionSet):
        return "version_set"
    raise TypeError(f"unknown PolicyChange: {change!r}")  # pragma: no cover


def describe_changes(changes: list[PolicyChange] | tuple[PolicyChange, ...]) -> tuple[str, ...]:
    return tuple(describe_change(change) for change in changes)


# ── apply() helpers ──────────────────────────────────────────────────────────


def _require_role_name(role: str) -> str:
    name = role.strip() if isinstance(role, str) else ""
    if not name:
        raise PolicyChangeError("validation_error", "role name must not be empty")
    return name


def _require_existing_role(doc: PolicyDocument, role: str) -> RoleBody:
    name = _require_role_name(role)
    body = doc.roles.get(name)
    if body is None:
        raise PolicyChangeError("role_not_found", f"role {name!r} not found")
    return body


def _validate_role_name_format(role: str) -> None:
    if not _ROLE_NAME_PATTERN.match(role):
        raise PolicyChangeError(
            "validation_error",
            f"role name {role!r} must match ^[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}$",
        )


def _validate_patterns(patterns: tuple[str, ...] | list[str], *, subject: str) -> list[str]:
    if not isinstance(patterns, (list, tuple)) or not all(
        isinstance(item, str) for item in patterns
    ):
        raise PolicyChangeError(
            "validation_error", f"{subject}: patterns must be a list of strings"
        )
    cleaned = [item.strip() for item in patterns]
    if any(not item for item in cleaned):
        raise PolicyChangeError("validation_error", f"{subject} has an empty allow pattern")
    return cleaned


def _apply_role_set(doc: PolicyDocument, change: RoleSet) -> None:
    name = _require_role_name(change.role)
    _validate_role_name_format(name)
    if not change.allow:
        raise PolicyChangeError(
            "validation_error", f"role {name!r} must declare at least one allow pattern"
        )
    patterns = _validate_patterns(change.allow, subject=f"role {name!r}")
    doc.roles[name] = RoleBody(description=change.description.strip(), allow=patterns)


def _apply_role_delete(doc: PolicyDocument, change: RoleDelete) -> None:
    _require_existing_role(doc, change.role)
    del doc.roles[_require_role_name(change.role)]


def _apply_allow_add(doc: PolicyDocument, change: AllowAdd) -> None:
    body = _require_existing_role(doc, change.role)
    name = _require_role_name(change.role)
    patterns = _validate_patterns(change.patterns, subject=f"role {name!r}")
    merged = list(body.allow)
    for pattern in patterns:
        if pattern not in merged:
            merged.append(pattern)
    body.allow = merged


def _apply_allow_remove(doc: PolicyDocument, change: AllowRemove) -> None:
    body = _require_existing_role(doc, change.role)
    name = _require_role_name(change.role)
    patterns = _validate_patterns(change.patterns, subject=f"role {name!r}")
    remaining = [item for item in body.allow if item not in patterns]
    if not remaining:
        raise PolicyChangeError(
            "validation_error",
            f"role {name!r} would have no allow patterns; delete the role instead",
        )
    body.allow = remaining


def _apply_list_set(doc: PolicyDocument, change: ListSet) -> None:
    if change.name not in LIST_FIELD_NAMES:
        raise PolicyChangeError(
            "validation_error",
            f"unknown list {change.name!r}; expected one of {sorted(LIST_FIELD_NAMES)}",
        )
    patterns = _validate_patterns(change.patterns, subject=f"list {change.name!r}")
    setattr(doc, change.name, patterns)


def _apply_version_set(doc: PolicyDocument, change: VersionSet) -> None:
    version = change.version.strip() if isinstance(change.version, str) else ""
    if not version:
        raise PolicyChangeError("validation_error", "version must be a non-empty string")
    doc.version = version


# ── from_yaml() helpers (mirrors keystone_mcp.rbac.policy's private helpers,
# kept separate because PolicyDocument's sections are lists/dicts, not the
# frozen tuples RbacPolicy stores) ──────────────────────────────────────────


def _string_list(raw: Any, field_name: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PolicyContractError(f"{field_name} must be a list when present")
    return [str(item).strip() for item in raw if str(item).strip()]


def _dispositions_dict(raw: Any) -> dict[str, list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyContractError("tool_dispositions must be a mapping when present")
    result: dict[str, list[str]] = {}
    for label, patterns in raw.items():
        label_text = str(label).strip()
        if not label_text:
            raise PolicyContractError("tool_dispositions labels must be non-empty")
        result[label_text] = _string_list(patterns, f"tool_dispositions.{label_text}")
    return result
