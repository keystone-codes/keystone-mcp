"""Published-name index on RouterRegistry."""

from __future__ import annotations

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry


def _registry() -> RouterRegistry:
    return RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")))


def test_published_name_index_follows_add_and_remove() -> None:
    reg = _registry()
    assert reg.has_published_name("users_list") is False

    reg.add_route("users_list", StubAdapter(), mode="live")
    assert reg.has_published_name("users_list") is True
    assert reg.owner_of_published_name("users_list") is not None

    route_key = reg.owner_of_published_name("users_list")
    assert route_key is not None
    removed = reg.remove_route(route_key)
    assert removed is not None
    assert reg.has_published_name("users_list") is False


def test_owner_of_published_name_unchanged() -> None:
    reg = _registry()
    reg.add_route("alpha_one", StubAdapter(), mode="live", namespace="alpha")
    reg.add_route("beta_two", StubAdapter(), mode="live", namespace="beta")

    assert reg.owner_of_published_name("alpha_alpha_one") is not None
    assert reg.owner_of_published_name("beta_beta_two") is not None
    assert reg.owner_of_published_name("missing_tool") is None

    first_key = reg.owner_of_published_name("alpha_alpha_one")
    reg.add_route("alpha_one", StubAdapter(), mode="live", namespace="alpha")
    assert reg.owner_of_published_name("alpha_alpha_one") == first_key
