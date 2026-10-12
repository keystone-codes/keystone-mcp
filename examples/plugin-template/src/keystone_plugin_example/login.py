"""Example OIDC login provider built on Keystone's generic implementation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from keystone_mcp.login.oidc import OidcLoginProvider, OidcProviderConfig
from keystone_mcp.plugins import LoginProviderConfig, PluginContext


class ExampleOidcProvider(OidcLoginProvider):
    """OIDC provider that maps group membership from a ``roles`` JWT claim by default."""


def create_provider(config: LoginProviderConfig, context: PluginContext) -> ExampleOidcProvider:
    options: Mapping[str, Any] = config.options
    title = config.title if config.title is not None else str(options.get("title", config.name))
    issuer = str(options.get("issuer", "")).strip()
    client_id = str(options.get("client_id", "")).strip()
    secret_env = str(options.get("client_secret_env", "")).strip()
    if not issuer:
        raise ValueError("issuer is required")
    if not client_id:
        raise ValueError("client_id is required")
    if not secret_env:
        raise ValueError("client_secret_env is required")
    oidc_config = OidcProviderConfig(
        name=config.name,
        title=title,
        issuer=issuer,
        client_id=client_id,
        client_secret=context.secret(secret_env),
        groups_claim=str(options.get("groups_claim", "roles")),
    )
    return ExampleOidcProvider(oidc_config)
