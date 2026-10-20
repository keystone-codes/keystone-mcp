"""The ``_guard_request_shutdown`` autouse fixture in ``conftest.py``.

A test whose code path reaches a real startup refusal must fail the test,
never send a real ``SIGTERM`` to the process running ``pytest``. These
checks run the fixture in a nested ``pytest`` invocation (``pytester``) so
a bug in the fixture cannot kill the outer test run that verifies it.
"""

from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]

_GUARD_CONFTEST = """
import pytest
from keystone_mcp import server

@pytest.fixture(autouse=True)
def _guard_request_shutdown(monkeypatch):
    calls = []

    def _record():
        calls.append(server._startup_failure_holder.get("error"))

    monkeypatch.setattr(server, "_request_shutdown", _record)
    yield
    if calls and server._request_shutdown is _record:
        pytest.fail(f"startup refused during the test: {calls[-1]!r}")
"""


def test_unsubstituted_shutdown_fails_the_test(pytester: pytest.Pytester) -> None:
    pytester.makeconftest(_GUARD_CONFTEST)
    pytester.makepyfile(
        """
        from keystone_mcp import server

        def test_triggers_real_shutdown():
            server._startup_failure_holder["error"] = RuntimeError("boom")
            server._request_shutdown()
        """
    )
    result = pytester.runpytest("-q")
    # The guard raises after ``yield``, in fixture teardown, so pytest files
    # it under "errors" rather than "failed" (its call-phase category) --
    # the test still shows up as broken and the run still exits non-zero.
    result.assert_outcomes(passed=1, errors=1)
    assert result.ret != 0
    result.stdout.fnmatch_lines(["*startup refused during the test*boom*"])


def test_substituted_shutdown_is_left_alone(pytester: pytest.Pytester) -> None:
    pytester.makeconftest(_GUARD_CONFTEST)
    pytester.makepyfile(
        """
        from keystone_mcp import server

        def test_own_fake_shutdown(monkeypatch):
            calls = []
            monkeypatch.setattr(server, "_request_shutdown", lambda: calls.append(1))
            server._startup_failure_holder["error"] = RuntimeError("boom")
            server._request_shutdown()
            assert calls == [1]
        """
    )
    result = pytester.runpytest("-q")
    result.assert_outcomes(passed=1)


def test_no_shutdown_call_passes(pytester: pytest.Pytester) -> None:
    pytester.makeconftest(_GUARD_CONFTEST)
    pytester.makepyfile(
        """
        def test_quiet():
            assert True
        """
    )
    result = pytester.runpytest("-q")
    result.assert_outcomes(passed=1)
