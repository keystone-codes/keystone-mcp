"""Load ``.env`` into the process environment before settings are built.

The server and the ``keystone-mcp`` CLI both need the same behaviour: read a
``KEY=VALUE`` file once, at the very start of the entry point, before
:func:`keystone_mcp.config.load_settings` (or ``Settings()``) runs. This module
is the single place that does the file reading and parsing; nothing in
``config.py`` touches the filesystem for this.

Precedence: a name already present in the environment (even with an empty
value) always wins over the file. Only names matching ``KEYSTONE_MCP_*`` are
loaded; anything else in the file is ignored without error. See
``load_env_file`` for the search rule and the file format.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import MutableMapping

from keystone_mcp.config import ConfigError

logger = logging.getLogger(__name__)

_ENV_FILE_VAR = "KEYSTONE_MCP_ENV_FILE"
_DEFAULT_ENV_FILE = ".env"
_KEY_PATTERN = re.compile(r"^KEYSTONE_MCP_[A-Z0-9_]+$")
_OWN_PREFIX = "KEYSTONE_MCP_"
_FORWARDED_ALLOW_IPS = "FORWARDED_ALLOW_IPS"


@dataclass(frozen=True)
class EnvFileResult:
    """Outcome of one :func:`load_env_file` call.

    ``path`` is ``None`` when loading was disabled or no file was found at the
    default location; ``loaded`` and ``skipped`` only ever name
    ``KEYSTONE_MCP_*`` variables (anything else in the file is silently
    ignored and appears in neither tuple).
    """

    path: Path | None
    loaded: tuple[str, ...]
    skipped: tuple[str, ...]
    ignored_forwarded_allow_ips: bool = False


def _strip_inline_comment(value: str) -> str:
    """Drop a `` #...`` trailing comment from an unquoted value.

    A space before ``#`` starts a comment that runs to the end of the line; a
    ``#`` with no preceding space is part of the value (so a password like
    ``pa#ss`` survives unquoted).
    """
    index = value.find(" #")
    if index == -1:
        return value
    return value[:index]


def _parse_value(raw: str, *, path: Path, line_number: int) -> str:
    value = raw.strip()
    if value and value[0] in ("'", '"'):
        quote = value[0]
        close = value.find(quote, 1)
        if close == -1:
            raise ConfigError(f"{path}:{line_number}: unterminated or malformed quoted value")
        rest = value[close + 1 :]
        if rest and not (rest.startswith(" ") and "#" in rest):
            raise ConfigError(f"{path}:{line_number}: unterminated or malformed quoted value")
        return value[1:close]
    return _strip_inline_comment(value).strip()


def _parse_env_file(path: Path) -> tuple[dict[str, str], bool]:
    """Parse ``path`` into ``{name: value}`` for ``KEYSTONE_MCP_*`` names only.

    A line's raw text is never included in a log message or an exception: a
    ``.env`` file is not necessarily ours alone (a shared file, or one with a
    multi-line secret such as a PEM block continuation), and echoing an
    unrecognised line back could leak a secret into a traceback or the log. A
    line with no ``=`` is refused only when it looks like one of ours (starts
    with ``KEYSTONE_MCP_``, after stripping an ``export `` prefix); anything
    else with no ``=`` is assumed to belong to someone else and is skipped
    with a warning naming only the file and line number.
    """
    values: dict[str, str] = {}
    forwarded_in_file = False
    text = path.read_text(encoding="utf-8")
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            if line.startswith(_OWN_PREFIX):
                raise ConfigError(f"{path}:{line_number}: expected KEY=VALUE")
            logger.warning(
                "%s:%d: line has no '=' and does not start with %s; skipped",
                path,
                line_number,
                _OWN_PREFIX,
            )
            continue
        key, _, raw_value = line.partition("=")
        key = key.strip()
        if key == _FORWARDED_ALLOW_IPS:
            forwarded_in_file = True
            continue
        if not _KEY_PATTERN.match(key):
            continue
        values[key] = _parse_value(raw_value, path=path, line_number=line_number)
    return values, forwarded_in_file


def load_env_file(environ: MutableMapping[str, str] | None = None) -> EnvFileResult:
    """Load ``KEYSTONE_MCP_*`` variables from a ``.env``-style file into ``environ``.

    Which file: ``KEYSTONE_MCP_ENV_FILE`` (read from ``environ``) decides.

    - Unset: ``.env`` in the current working directory; missing is not an
      error (loading is simply a no-op).
    - Set and non-empty: that path, resolved relative to the current working
      directory; missing is a :class:`ConfigError`.
    - Set to the empty string: loading is disabled entirely.

    No other location is searched (not the package directory, not the home
    directory, not ``/etc``).

    A name already present in ``environ`` — even with an empty value — is left
    untouched and is reported in ``skipped`` rather than ``loaded``.
    """
    if environ is None:
        import os

        environ = os.environ

    override_raw = environ.get(_ENV_FILE_VAR)
    if override_raw is not None:
        if override_raw == "":
            return EnvFileResult(path=None, loaded=(), skipped=())
        path = Path(override_raw)
        if not path.is_file():
            raise ConfigError(f"{_ENV_FILE_VAR} points at a missing file: {override_raw}")
    else:
        path = Path(_DEFAULT_ENV_FILE)
        if not path.is_file():
            return EnvFileResult(path=None, loaded=(), skipped=())

    file_values, forwarded_in_file = _parse_env_file(path)
    ignored_forwarded = forwarded_in_file and _FORWARDED_ALLOW_IPS not in environ

    loaded: list[str] = []
    skipped: list[str] = []
    for key, value in file_values.items():
        if key in environ:
            skipped.append(key)
            continue
        environ[key] = value
        loaded.append(key)

    return EnvFileResult(
        path=path,
        loaded=tuple(loaded),
        skipped=tuple(skipped),
        ignored_forwarded_allow_ips=ignored_forwarded,
    )
