"""RBAC policy contract: YAML structure, glob matching, catalog validation.

The policy file is the single source of truth for role names, allow patterns,
the human-identity gate, the critical-tool set, reserved allow patterns and
matrix dispositions. No tool name or role name is hardcoded here.

See ``docs/rbac-policy-format.md`` for the normative file format.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_POLICY_RELATIVE = Path("config") / "rbac-policy.yaml"

#: Top-level keys accepted in a policy file. Anything else is a contract error.
POLICY_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "version",
        "default_deny",
        "roles",
        "deny",
        "requires_human_identity",
        "critical_tools",
        "reserved_allow_patterns",
        "tool_dispositions",
    }
)

#: Disposition used for matrix generation when no ``tool_dispositions`` entry matches.
FALLBACK_DISPOSITION = "W"


class PolicyContractError(ValueError):
    """Raised when a policy file violates the contract."""


@dataclass(frozen=True, slots=True)
class RolePolicy:
    """Allow patterns for a single RBAC role. The role name is free-form."""

    name: str
    description: str
    allow_patterns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RbacPolicy:
    """Parsed RBAC policy contract."""

    version: str
    default_deny: bool
    roles: tuple[RolePolicy, ...]
    deny_patterns: tuple[str, ...] = ()
    human_identity_patterns: tuple[str, ...] = ()
    critical_tool_patterns: tuple[str, ...] = ()
    reserved_allow_patterns: tuple[str, ...] = ()
    #: Disposition label -> glob patterns, in file order (first match wins).
    tool_dispositions: tuple[tuple[str, tuple[str, ...]], ...] = field(default=())
    source_path: Path | None = None

    @property
    def role_names(self) -> frozenset[str]:
        return frozenset(role.name for role in self.roles)

    def role(self, name: str) -> RolePolicy | None:
        for item in self.roles:
            if item.name == name:
                return item
        return None

    def is_globally_denied(self, tool_name: str) -> bool:
        """Whether a tool is denied for every role (overrides allow globs, including ``*``)."""
        return _matches_any(tool_name, self.deny_patterns)

    def allows_role(self, role: str, tool_name: str) -> bool:
        """Whether a single role permits a published tool name."""
        if self.is_globally_denied(tool_name):
            return False
        if not self.default_deny:
            return True
        role_policy = self.role(role)
        if role_policy is None:
            return False
        return _matches_any(tool_name, role_policy.allow_patterns)

    def allows(self, roles: frozenset[str], tool_name: str) -> bool:
        """Union of allow patterns across all assigned roles (multi-role)."""
        if not roles:
            return False
        return any(self.allows_role(role, tool_name) for role in roles)

    def allowed_by_any_role(self, tool_name: str) -> bool:
        """Whether at least one declared role can reach the tool."""
        return any(self.allows_role(role.name, tool_name) for role in self.roles)

    def decisions_for_tool(self, tool_name: str) -> dict[str, bool]:
        """Explicit allow/deny per declared role for one published tool."""
        return {role: self.allows_role(role, tool_name) for role in sorted(self.role_names)}

    def requires_human_identity(self, tool_name: str) -> bool:
        """Whether the tool may only run under an interactive human login."""
        return _matches_any(tool_name, self.human_identity_patterns)

    def is_critical_tool(self, tool_name: str) -> bool:
        """Whether the policy marks the tool as critical (allow-cache bypass).

        Platform built-ins are added on top of this by
        :func:`keystone_mcp.user_directory.critical.is_critical_tool`.
        """
        return _matches_any(tool_name, self.critical_tool_patterns)

    def disposition(self, tool_name: str) -> str:
        """Matrix disposition label for a tool; ``FALLBACK_DISPOSITION`` when unmatched."""
        for label, patterns in self.tool_dispositions:
            if _matches_any(tool_name, patterns):
                return label
        return FALLBACK_DISPOSITION

    def literal_allow_names(self) -> frozenset[str]:
        """Allow patterns that are plain tool names (no glob metacharacters)."""
        names: set[str] = set()
        for role in self.roles:
            names.update(pattern for pattern in role.allow_patterns if not _is_glob(pattern))
        for _label, patterns in self.tool_dispositions:
            names.update(pattern for pattern in patterns if not _is_glob(pattern))
        return frozenset(names)


@dataclass(frozen=True, slots=True)
class CatalogValidationResult:
    """Outcome of validating policy against a tool catalog."""

    tool_names: frozenset[str]
    unmatched_allow_patterns: tuple[str, ...]
    unreachable_tools: frozenset[str]

    @property
    def ok(self) -> bool:
        """True when no allow pattern is unreachable.

        Unreachable tools are reported but never fatal: a deployment may
        deliberately publish a tool no role can call.
        """
        return not self.unmatched_allow_patterns


def default_policy_path() -> Path:
    """Default rbac-policy.yaml path relative to the repository root."""
    return _REPO_ROOT / DEFAULT_POLICY_RELATIVE


def load_policy_file(path: Path | str) -> RbacPolicy:
    """Load and validate a policy file from disk."""
    policy, _content_hash = load_policy_file_with_hash(path)
    return policy


def load_policy_file_with_hash(path: Path | str) -> tuple[RbacPolicy, str]:
    """Load policy and return SHA-256 of the exact bytes that were parsed."""
    policy_path = Path(path)
    raw_bytes = policy_path.read_bytes()
    raw = raw_bytes.decode("utf-8")
    policy = parse_policy_yaml(raw, source_path=policy_path)
    validate_policy_structure(policy)
    return policy, hash_policy_bytes(raw_bytes)


def hash_policy_bytes(raw_bytes: bytes) -> str:
    """SHA-256 digest of policy file bytes (audit / hot-reload marker)."""
    return hashlib.sha256(raw_bytes).hexdigest()


def load_policy(path: Path | str | None = None) -> RbacPolicy:
    """Load the default or an explicit policy file."""
    return load_policy_file(path or default_policy_path())


def parse_policy_yaml(raw: str, *, source_path: Path | None = None) -> RbacPolicy:
    """Parse policy YAML text into an :class:`RbacPolicy`."""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyContractError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyContractError("policy root must be a mapping")
    return _build_policy(data, source_path=source_path)


def policy_content_hash(policy_path: Path | str) -> str:
    """SHA-256 of the policy file bytes (audit / hot-reload marker)."""
    return hash_policy_bytes(Path(policy_path).read_bytes())


def validate_policy_structure(policy: RbacPolicy) -> None:
    """Fail fast on contract violations independent of any catalog."""
    if not policy.default_deny:
        raise PolicyContractError("default_deny must be true (deny-by-default)")
    if not policy.version.strip():
        raise PolicyContractError("version must be a non-empty string")
    if not policy.roles:
        raise PolicyContractError("roles must declare at least one role")

    seen: set[str] = set()
    for role in policy.roles:
        if not role.name:
            raise PolicyContractError("role names must be non-empty strings")
        if role.name in seen:
            raise PolicyContractError(f"duplicate role {role.name!r}")
        seen.add(role.name)
        if not role.allow_patterns:
            raise PolicyContractError(f"role {role.name!r} must declare at least one allow pattern")
        for pattern in role.allow_patterns:
            if not pattern.strip():
                raise PolicyContractError(f"role {role.name!r} has an empty allow pattern")


def validate_policy_against_catalog(
    policy: RbacPolicy,
    active_tool_names: frozenset[str],
    *,
    reserved_tool_names: frozenset[str] = frozenset(),
    wip_tool_names: frozenset[str] = frozenset(),
) -> CatalogValidationResult:
    """Check allow-pattern reachability and role coverage against a catalog.

    ``active_tool_names`` are names known to exist. ``reserved_tool_names`` are
    names declared before publication; ``wip_tool_names`` are work-in-progress
    names. A pattern listed in ``policy.reserved_allow_patterns`` may match only
    reserved or WIP names; any other pattern must match something in
    ``active | reserved | wip``.
    """
    validate_policy_structure(policy)
    active = frozenset(active_tool_names)
    reserved = frozenset(reserved_tool_names)
    wip = frozenset(wip_tool_names)
    catalog = active | reserved
    pattern_catalog = catalog | wip
    forward_looking = reserved | wip

    unmatched: list[str] = []
    for role in policy.roles:
        for pattern in role.allow_patterns:
            if pattern == "*":
                if not pattern_catalog:
                    unmatched.append(f"{role.name}:{pattern}")
                continue
            if pattern in policy.reserved_allow_patterns:
                if not _pattern_matches_any(pattern, forward_looking):
                    unmatched.append(f"{role.name}:{pattern}")
                continue
            if not _pattern_matches_any(pattern, pattern_catalog):
                unmatched.append(f"{role.name}:{pattern}")

    intentionally_denied = frozenset(policy.deny_patterns) & catalog
    unreachable = frozenset(
        tool
        for tool in catalog
        if not policy.allowed_by_any_role(tool) and tool not in intentionally_denied
    )

    return CatalogValidationResult(
        tool_names=catalog,
        unmatched_allow_patterns=tuple(unmatched),
        unreachable_tools=unreachable,
    )


def assert_catalog_validation(
    policy: RbacPolicy,
    active_tool_names: frozenset[str],
    *,
    reserved_tool_names: frozenset[str] = frozenset(),
    wip_tool_names: frozenset[str] = frozenset(),
) -> CatalogValidationResult:
    """Validate policy against a static catalog; raise on unreachable patterns.

    Tools that no role can reach are logged as a warning, never refused: that
    is a deployment choice, not a contract violation.
    """
    result = validate_policy_against_catalog(
        policy,
        active_tool_names,
        reserved_tool_names=reserved_tool_names,
        wip_tool_names=wip_tool_names,
    )
    if result.unmatched_allow_patterns:
        raise PolicyContractError(
            "unmatched allow patterns (typo or missing catalog/WIP entry): "
            + ", ".join(result.unmatched_allow_patterns)
        )
    log_unreachable_tools(result)
    return result


def log_unreachable_tools(result: CatalogValidationResult) -> None:
    """Emit a WARNING listing tools that no role can reach."""
    if result.unreachable_tools:
        logger.warning(
            "rbac policy leaves %d tool(s) unreachable by any role: %s",
            len(result.unreachable_tools),
            ", ".join(sorted(result.unreachable_tools)),
        )


def _build_policy(data: dict[str, Any], *, source_path: Path | None) -> RbacPolicy:
    unknown = sorted(set(map(str, data)) - POLICY_TOP_LEVEL_KEYS)
    if unknown:
        raise PolicyContractError(
            "unknown top-level keys in policy: "
            + ", ".join(unknown)
            + f" (allowed: {', '.join(sorted(POLICY_TOP_LEVEL_KEYS))})"
        )

    version = str(data.get("version", "")).strip()
    default_deny = _require_bool(data.get("default_deny", True), "default_deny")
    roles_raw = data.get("roles")
    if not isinstance(roles_raw, dict):
        raise PolicyContractError("roles must be a mapping")

    roles: list[RolePolicy] = []
    for name, body in roles_raw.items():
        if not isinstance(body, dict):
            raise PolicyContractError(f"role {name!r} must be a mapping")
        allow_raw = body.get("allow")
        if not isinstance(allow_raw, list) or not allow_raw:
            raise PolicyContractError(f"role {name!r}.allow must be a non-empty list")
        patterns = tuple(str(item).strip() for item in allow_raw)
        description = str(body.get("description", "")).strip()
        roles.append(
            RolePolicy(
                name=str(name).strip(),
                description=description,
                allow_patterns=patterns,
            )
        )

    return RbacPolicy(
        version=version,
        default_deny=default_deny,
        roles=tuple(roles),
        deny_patterns=_pattern_list(data.get("deny"), "deny"),
        human_identity_patterns=_pattern_list(
            data.get("requires_human_identity"), "requires_human_identity"
        ),
        critical_tool_patterns=_pattern_list(data.get("critical_tools"), "critical_tools"),
        reserved_allow_patterns=_pattern_list(
            data.get("reserved_allow_patterns"), "reserved_allow_patterns"
        ),
        tool_dispositions=_dispositions(data.get("tool_dispositions")),
        source_path=source_path,
    )


def _pattern_list(raw: Any, field_name: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyContractError(f"{field_name} must be a list when present")
    return tuple(str(item).strip() for item in raw if str(item).strip())


def _dispositions(raw: Any) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise PolicyContractError("tool_dispositions must be a mapping when present")
    entries: list[tuple[str, tuple[str, ...]]] = []
    for label, patterns in raw.items():
        label_text = str(label).strip()
        if not label_text:
            raise PolicyContractError("tool_dispositions labels must be non-empty")
        entries.append((label_text, _pattern_list(patterns, f"tool_dispositions.{label_text}")))
    return tuple(entries)


def _matches_any(tool_name: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if pattern == "*" or fnmatch(tool_name, pattern):
            return True
    return False


def _require_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise PolicyContractError(f"{field_name} must be a boolean, got {type(value).__name__}")


def _pattern_matches_any(pattern: str, tool_names: frozenset[str]) -> bool:
    if pattern == "*":
        return bool(tool_names)
    return any(fnmatch(name, pattern) for name in tool_names)


def _is_glob(pattern: str) -> bool:
    return any(char in pattern for char in "*?[")
