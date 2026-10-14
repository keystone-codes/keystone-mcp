"""Tests for users-directory plugin YAML config loading."""

from __future__ import annotations

import pytest

from keystone_mcp.config import ConfigError
from keystone_mcp.user_directory.backend_config import load_users_backend_config


def test_rejects_client_secret_key(tmp_path) -> None:
    path = tmp_path / "backend.yaml"
    path.write_text("client_secret: embedded\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="client_secret"):
        load_users_backend_config(str(path))


def test_rejects_secret_inside_list(tmp_path) -> None:
    path = tmp_path / "backend.yaml"
    path.write_text("servers:\n  - password: x\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="password"):
        load_users_backend_config(str(path))


def test_allows_secret_env_reference(tmp_path) -> None:
    path = tmp_path / "backend.yaml"
    path.write_text("client_secret_env: CLIENT_SECRET\n", encoding="utf-8")
    assert load_users_backend_config(str(path)) == {"client_secret_env": "CLIENT_SECRET"}


def test_allows_unrelated_keys_containing_no_secret_words(tmp_path) -> None:
    path = tmp_path / "backend.yaml"
    path.write_text("timeout_seconds: 5\n", encoding="utf-8")
    assert load_users_backend_config(str(path)) == {"timeout_seconds": 5}
