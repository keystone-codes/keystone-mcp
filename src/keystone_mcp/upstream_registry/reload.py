"""Hot-reload helpers for the upstream registry file (F03)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from keystone_mcp.config import Settings, UpstreamConfig
from keystone_mcp.identity_assertion import resolve_identity_secret
from keystone_mcp.secrets import read_secret


def upstream_registry_file_hash(settings: Settings) -> str | None:
    """SHA-256 hex digest of the registry file bytes, or ``None`` when not file-backed."""
    path_raw = settings.upstreams_path.strip()
    if not path_raw:
        return None
    path = Path(path_raw)
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def upstream_registry_info_hash(content_hash: str | None) -> str | None:
    """First 12 hex chars for ``keystone_mcp_upstream_registry_info``."""
    if content_hash is None:
        return None
    return content_hash[:12]


def enabled_upstream_map(configs: tuple[UpstreamConfig, ...]) -> dict[str, UpstreamConfig]:
    return {cfg.namespace: cfg for cfg in configs if cfg.enabled}


def _secret_digest(value: str | bytes) -> str:
    data = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def upstream_secrets_fingerprint(cfg: UpstreamConfig) -> tuple[tuple[str, str], ...]:
    """Hashes of secret values referenced by ``cfg`` (never the values themselves)."""
    parts: list[tuple[str, str]] = []
    if cfg.bearer_env:
        raw = (read_secret(cfg.bearer_env) or "").strip()
        parts.append((f"bearer:{cfg.bearer_env}", _secret_digest(raw)))
    if cfg.identity_secret_env:
        try:
            secret = resolve_identity_secret(cfg.name, cfg.identity_secret_env)
        except ValueError:
            secret = ""
        parts.append((f"identity:{cfg.identity_secret_env}", _secret_digest(secret)))
    for child_name, env_name in cfg.env_from:
        raw = (read_secret(env_name) or "").strip()
        parts.append((f"stdio_env:{child_name}:{env_name}", _secret_digest(raw)))
    return tuple(sorted(parts))


def upstream_entry_equivalent(
    left: UpstreamConfig,
    right: UpstreamConfig,
    *,
    compare_secrets: bool,
) -> bool:
    if left == right:
        if not compare_secrets:
            return True
        return upstream_secrets_fingerprint(left) == upstream_secrets_fingerprint(right)
    return False


@dataclass(frozen=True, slots=True)
class RegistryDiff:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]


def diff_upstream_registry(
    previous: dict[str, UpstreamConfig],
    current: dict[str, UpstreamConfig],
    *,
    force_secrets: bool,
    applied_secret_fingerprints: dict[str, tuple[tuple[str, str], ...]] | None = None,
) -> RegistryDiff:
    prev_ns = set(previous)
    cur_ns = set(current)
    added = tuple(sorted(cur_ns - prev_ns))
    removed = tuple(sorted(prev_ns - cur_ns))
    changed: list[str] = []
    for namespace in sorted(prev_ns & cur_ns):
        old_cfg = previous[namespace]
        new_cfg = current[namespace]
        if old_cfg != new_cfg:
            changed.append(namespace)
            continue
        if force_secrets:
            current_fp = upstream_secrets_fingerprint(new_cfg)
            if applied_secret_fingerprints is not None:
                applied = applied_secret_fingerprints.get(namespace)
                if applied is None or applied != current_fp:
                    changed.append(namespace)
            elif not upstream_entry_equivalent(
                old_cfg, new_cfg, compare_secrets=True
            ):
                changed.append(namespace)
    return RegistryDiff(added=added, removed=removed, changed=tuple(changed))
