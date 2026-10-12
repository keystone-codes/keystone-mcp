"""Packaging and plugin metadata checks for contract tests."""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys

from keystone_mcp.contract_tests import (
    AdminDirectoryContract,
    ApiKeyDirectoryContract,
    FormLoginProviderContract,
    OidcLoginProviderContract,
    ServiceAccountDirectoryContract,
    UserDirectoryContract,
)


def test_import_keystone_does_not_require_pytest() -> None:
    script = """
import sys
sys.modules["pytest"] = None
import keystone_mcp
import keystone_mcp.server
import keystone_mcp.login
import keystone_mcp.user_directory
"""
    subprocess.run([sys.executable, "-c", script], check=True)


def test_contract_classes_are_marked() -> None:
    for cls in (
        UserDirectoryContract,
        AdminDirectoryContract,
        ServiceAccountDirectoryContract,
        ApiKeyDirectoryContract,
        OidcLoginProviderContract,
        FormLoginProviderContract,
    ):
        marks = getattr(cls, "pytestmark", ())
        if not isinstance(marks, tuple):
            marks = (marks,)
        assert any(getattr(mark, "name", None) == "keystone_contract" for mark in marks)


def test_plugin_not_registered_as_pytest11() -> None:
    entry_points = importlib.metadata.entry_points()
    group = entry_points.select(group="pytest11")
    names = {ep.name for ep in group}
    assert "keystone_mcp.contract_tests" not in names
    assert "contract_tests" not in names
