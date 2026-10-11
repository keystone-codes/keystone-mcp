"""HTTP path and OAuth resource URL configuration tests."""

from __future__ import annotations

from keystone_mcp.config import (
    Settings,
    resources_equivalent,
)


def test_default_http_path_is_root():
    settings = Settings(base_url="https://mcp.example.com")
    assert settings.http_path == "/"
    assert settings.resource_url == "https://mcp.example.com"
    assert settings.transport_url == "https://mcp.example.com/"
    assert settings.protected_resource_metadata_path == "/.well-known/oauth-protected-resource"


def test_legacy_mcp_path_is_configurable():
    settings = Settings(base_url="http://localhost:8080", http_path_raw="/mcp")
    assert settings.http_path == "/mcp"
    assert settings.resource_url == "http://localhost:8080/mcp"
    assert settings.transport_url == "http://localhost:8080/mcp/"
    assert settings.protected_resource_metadata_path == "/.well-known/oauth-protected-resource/mcp"


def test_resources_equivalent_ignores_root_trailing_slash():
    assert resources_equivalent(
        "https://mcp.example.com",
        "https://mcp.example.com/",
    )
    assert not resources_equivalent(
        "https://mcp.example.com",
        "https://mcp.example.com/mcp",
    )
