"""Shared regex-based extraction of ``KEYSTONE_MCP_*`` variable names.

Used by ``tests/test_env_docs_sync.py`` and by the cards that add to
``config.py::REMOVED_VARIABLES`` (Z01, Z03, Z09) to check that a removed
variable is not still read by the code, and that it is documented where it
should be.

Plain regexes, not an import of ``keystone_mcp.config`` or introspection of
its dataclass, since names living inside ``default_factory=lambda`` cannot be
recovered that way.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"

# Matches every place the code reads a KEYSTONE_MCP_* variable: the _env*
# helpers in config.py, and direct os.environ/os.getenv reads anywhere else
# in src/ (e.g. a dedicated .env loader).
CODE_VARIABLE_PATTERN = re.compile(
    r"(?:_env(?:_int|_float|_bool)?\(|os\.environ\.get\(|os\.getenv\(|os\.environ\[)"
    r"\s*[\"'](KEYSTONE_MCP_[A-Z0-9_]+)[\"']"
)

# Matches a variable assignment line in .env.example, commented out or not.
# Repeated names (e.g. mentioned again in a later section) are fine, we only
# care about the resulting set.
ENV_EXAMPLE_VARIABLE_PATTERN = re.compile(
    r"^\s*#?\s*(KEYSTONE_MCP_[A-Z0-9_]+)=",
    re.MULTILINE,
)

# Matches the first column of a Markdown table row in docs/environment.md
# (or any docs/contrib/*.md page, same shape),
# e.g. "| `KEYSTONE_MCP_BASE_URL` | `http://localhost:8080` | ... |".
DOCS_VARIABLE_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|",
    re.MULTILINE,
)

#: ``src/keystone_mcp/contrib/`` — reference code for forks. Its settings use
#: the ``KEYSTONE_MCP_CONTRIB_*`` prefix, are documented in ``docs/contrib/``
#: (not ``docs/environment.md``) and are not listed in ``.env.example``; see
#: ``contrib_variables()`` / ``contrib_doc_variables()`` below.
CONTRIB_ROOT = SRC_ROOT / "contrib"


def code_variables(root: Path = SRC_ROOT) -> set[str]:
    """Every ``KEYSTONE_MCP_*`` name read by the code under ``root``.

    Excludes ``keystone_mcp.contrib`` by default: contrib variables are a
    separate namespace, checked by ``contrib_variables()`` instead. Pass an
    explicit ``root`` to opt back in.
    """
    names: set[str] = set()
    for path in root.rglob("*.py"):
        if root == SRC_ROOT and CONTRIB_ROOT in path.parents:
            continue
        text = path.read_text(encoding="utf-8")
        names.update(CODE_VARIABLE_PATTERN.findall(text))
    return names


def contrib_variables() -> set[str]:
    """Every ``KEYSTONE_MCP_*`` name read by the code under ``contrib/``."""
    names: set[str] = set()
    for path in CONTRIB_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        names.update(CODE_VARIABLE_PATTERN.findall(text))
    return names


def contrib_doc_variables(root: Path | None = None) -> set[str]:
    """Every ``KEYSTONE_MCP_*`` name in the first column of a table in any
    ``docs/contrib/*.md`` page."""
    docs_root = root if root is not None else REPO_ROOT / "docs" / "contrib"
    names: set[str] = set()
    for path in docs_root.glob("*.md"):
        text = path.read_text(encoding="utf-8")
        names.update(DOCS_VARIABLE_PATTERN.findall(text))
    return names


def env_example_variables(path: Path) -> set[str]:
    """Every ``KEYSTONE_MCP_*`` name assigned (commented or not) in ``path``."""
    text = path.read_text(encoding="utf-8")
    return set(ENV_EXAMPLE_VARIABLE_PATTERN.findall(text))


def environment_md_variables(path: Path) -> set[str]:
    """Every ``KEYSTONE_MCP_*`` name in the first column of a table in ``path``."""
    text = path.read_text(encoding="utf-8")
    return set(DOCS_VARIABLE_PATTERN.findall(text))
