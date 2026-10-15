"""Pins the httpx2 boundary ``McpProxyAdapter`` builds for fastmcp's transport.

Also guards that Keystone does not import ``mcp.shared._httpx_utils`` at
runtime (only under ``TYPE_CHECKING``).

fastmcp 4's ``StreamableHttpTransport`` hands its HTTP client factory an
``auth`` object built for ``httpx2`` (``fastmcp.client.auth.bearer.BearerAuth``),
which an ``httpx.AsyncClient`` rejects with ``TypeError: Invalid "auth"
argument`` -- the single biggest break found migrating off fastmcp 3.4.4 (see
the fastmcp 4 migration spike report (private task archive)). This guards
against a regression back to ``httpx``.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import httpx2

from keystone_mcp.adapters.mcp_proxy import _http_client_factory

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"


def test_proxy_http_factory_builds_httpx2_client():
    client = _http_client_factory(5.0)(headers=None, timeout=None, auth=None)

    assert isinstance(client, httpx2.AsyncClient)
    assert client.timeout.read == 5.0
    assert client.timeout.connect == 5.0


def _runtime_imports_httpx_utils(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
        ):
            ranges.append(
                (node.lineno, max(getattr(n, "lineno", node.lineno) for n in ast.walk(node)))
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        if any(start <= node.lineno <= end for start, end in ranges):
            continue
        if node.module == "mcp.shared._httpx_utils":
            return True
    return False


def test_mcp_private_modules_not_imported_at_runtime() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in SRC_ROOT.rglob("*.py")
        if _runtime_imports_httpx_utils(path)
    ]
    assert offenders == [], f"runtime import of mcp.shared._httpx_utils in {offenders}"

    script = "import keystone_mcp.server  # noqa: F401\n"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
