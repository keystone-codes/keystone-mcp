"""Upper bounds on runtime dependencies match the locked major line."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
UV_LOCK = ROOT / "uv.lock"


def _locked_version(name: str) -> tuple[int, ...]:
    data = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    for package in data["package"]:
        if package["name"] == name:
            return tuple(int(part) for part in package["version"].split("."))
    raise KeyError(name)


def _dependency_line(name: str) -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    for line in data["project"]["dependencies"]:
        pkg = line.split("[")[0].split(",")[0].split(">=")[0].split("==")[0].strip()
        if pkg == name:
            return line
    pytest.fail(f"dependency {name!r} not found in pyproject.toml")


def _upper_exclusive_major(spec: str) -> int:
    match = re.search(r",<(\d+)", spec)
    assert match is not None, f"expected an upper bound in {spec!r}"
    return int(match.group(1))


@pytest.mark.parametrize(
    "name",
    ["starlette", "pydantic", "redis", "sqlalchemy", "alembic"],
)
def test_major_upper_bounds(name: str) -> None:
    spec = _dependency_line(name)
    assert "<" in spec
    locked = _locked_version(name)
    upper_major = _upper_exclusive_major(spec)
    assert upper_major > locked[0], (
        f"{name}: upper major {upper_major} must exceed locked major {locked[0]} "
        f"(locked {'.'.join(str(p) for p in locked)})"
    )
