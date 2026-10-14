"""Read secret values from the environment or ``<NAME>_FILE`` paths."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Mapping
from pathlib import Path

logger = logging.getLogger(__name__)

SECRET_FILE_SUFFIX = "_FILE"
MAX_SECRET_FILE_BYTES = 65536

_warned_both_set: set[str] = set()


def _config_error_class():
    from keystone_mcp.config import ConfigError

    return ConfigError


def _raise_secret_file_error(message: str) -> None:
    raise _config_error_class()(message)


def _strip_one_trailing_newline(text: str) -> str:
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def _read_file_at_path(name: str, path: Path) -> str:
    file_var = f"{name}{SECRET_FILE_SUFFIX}"
    try:
        if path.is_dir():
            _raise_secret_file_error(f"{file_var}: cannot read {path}: is a directory")
        raw = path.read_bytes()
    except OSError as exc:
        _raise_secret_file_error(f"{file_var}: cannot read {path}: {exc}")
    if len(raw) > MAX_SECRET_FILE_BYTES:
        _raise_secret_file_error(
            f"{file_var}: cannot read {path}: exceeds {MAX_SECRET_FILE_BYTES} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _raise_secret_file_error(f"{file_var}: cannot read {path}: {exc}")
    return _strip_one_trailing_newline(text)


def _warn_both_set(name: str, file_var: str) -> None:
    if name in _warned_both_set:
        return
    _warned_both_set.add(name)
    logger.warning("%s and %s are both set; using the file", name, file_var)


def read_secret(name: str, *, environ: Mapping[str, str] | None = None) -> str | None:
    """Value of *name*, or of the file named by *name*_FILE; ``None`` when neither is set."""
    env = os.environ if environ is None else environ
    file_var = f"{name}{SECRET_FILE_SUFFIX}"
    file_path_raw = env.get(file_var, "").strip()
    direct = env.get(name)

    if file_path_raw:
        if direct is not None and direct.strip():
            _warn_both_set(name, file_var)
        return _read_file_at_path(name, Path(file_path_raw))

    if direct is not None:
        return direct
    return None


def secret_is_set(name: str, *, environ: Mapping[str, str] | None = None) -> bool:
    """True when *name* or ``name_FILE`` is present in the environment."""
    env = os.environ if environ is None else environ
    if name in env:
        return True
    file_var = f"{name}{SECRET_FILE_SUFFIX}"
    return bool(env.get(file_var, "").strip())


def secret_sources_conflicts(
    names: Iterable[str], environ: Mapping[str, str] | None = None
) -> list[str]:
    """Names for which both the variable and ``name_FILE`` are set (non-empty file path)."""
    env = os.environ if environ is None else environ
    conflicts: list[str] = []
    for name in names:
        file_var = f"{name}{SECRET_FILE_SUFFIX}"
        if env.get(name, "").strip() and env.get(file_var, "").strip():
            conflicts.append(name)
    return conflicts


def check_secret_files(environ: Mapping[str, str] | None = None) -> list[str]:
    """Validate every ``SECRET_VARIABLES`` ``*_FILE`` path; return error messages."""
    from keystone_mcp.config import SECRET_VARIABLES

    env = os.environ if environ is None else environ
    errors: list[str] = []
    for name in SECRET_VARIABLES:
        file_var = f"{name}{SECRET_FILE_SUFFIX}"
        path_raw = env.get(file_var, "").strip()
        if not path_raw:
            continue
        try:
            _read_file_at_path(name, Path(path_raw))
        except _config_error_class() as exc:
            errors.append(str(exc))
    return errors
