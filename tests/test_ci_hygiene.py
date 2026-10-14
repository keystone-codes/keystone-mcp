"""Guard against the 0.4.0 test-stand crutches coming back.

In 0.3.1/0.4.0, Streamable HTTP end-to-end flakiness was papered over with
three crutches: forcing a handful of e2e tests to collect first
(``pytest_collection_modifyitems`` + ``_EARLY_MCP_HTTP_E2E_TESTS`` in
``conftest.py``), retrying the MCP client around transient transport errors
(``retry_transient_mcp_errors``/``mcp_client_session``, up to eight
attempts), and rerunning the whole suite twice in CI (``pytest-rerunfailures``
and ``--reruns`` in ``test-gate.yml``). The fastmcp 4.x migration
removed all three. These tests make sure they do not quietly return — a
flaky test is a bug to fix, not a retry to add back.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
TESTS_DIR = REPO_ROOT / "tests"

# This file itself is named after, and talks about, the very crutch it
# guards against ("retry" + "mcp" both appear in this module's own test
# names and prose), so it is excluded from the function-name scan below —
# otherwise the guard would permanently fail on itself.
_SELF_PATH = Path(__file__).resolve()


def test_no_reruns_in_ci():
    """No workflow file reruns failed tests or replays a cached last-failed set."""
    workflow_files = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    assert workflow_files, f"no workflow files found under {WORKFLOWS_DIR}"
    for path in workflow_files:
        text = path.read_text(encoding="utf-8")
        assert "--reruns" not in text, (
            f"{path.name} reruns failed tests (--reruns); fix the flaky test instead"
        )
        assert "--lf" not in text, (
            f"{path.name} replays only last-failed tests (--lf); the full suite must run"
        )


def test_no_test_reordering_hook():
    """No file under tests/ (conftest.py or otherwise) forces a collection order.

    ``pytest_collection_modifyitems`` only takes effect from a conftest.py,
    but the crutch being guarded against here is the hook function itself
    reappearing — including tucked into a helper module under
    ``tests/support`` and imported from a conftest.py, which would still
    slip past a search limited to files literally named ``conftest.py``.
    """
    test_files = sorted(TESTS_DIR.rglob("*.py"))
    assert test_files, f"no Python files found under {TESTS_DIR}"
    for path in test_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "pytest_collection_modifyitems"
            ):
                raise AssertionError(
                    f"{path}: defines pytest_collection_modifyitems, which reorders "
                    "or filters test collection; do not force e2e tests to run first"
                )


def test_rerun_plugins_not_installed():
    """Neither pytest-rerunfailures nor flaky is an installed dependency."""
    assert importlib.util.find_spec("pytest_rerunfailures") is None, (
        "pytest-rerunfailures is installed; it must not be a dev dependency"
    )
    assert importlib.util.find_spec("flaky") is None, (
        "flaky is installed; it must not be a dev dependency"
    )


def test_no_retry_loops_around_mcp_client():
    """No test helper retries around the MCP client under another name.

    A crude but sufficient net: any function (sync or async, anywhere in
    ``tests/``) whose name contains "retry" and also "mcp" or "transient" is
    almost certainly a reincarnation of ``retry_transient_mcp_errors``.
    Legitimate product-code retry settings (e.g.
    ``KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES``) live outside ``tests/`` and
    are not touched by this check.
    """
    offenders: list[str] = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        if path.resolve() == _SELF_PATH:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            lowered = node.name.lower()
            if "retry" in lowered and ("mcp" in lowered or "transient" in lowered):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}:{node.name}")
    assert not offenders, (
        "found function(s) that look like a retry loop around the MCP client: "
        + ", ".join(offenders)
    )
