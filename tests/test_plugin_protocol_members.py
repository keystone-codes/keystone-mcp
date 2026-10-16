"""Frozen 0.5 protocol member lists stay aligned with the protocol definitions."""

from __future__ import annotations

import pytest

try:
    from typing import get_protocol_members as _get_protocol_members
except ImportError:
    from typing_extensions import get_protocol_members as _get_protocol_members

from keystone_mcp.login.protocol import FormLoginProvider, LoginProvider, RedirectLoginProvider
from keystone_mcp.plugins import PROTOCOL_MEMBERS_0_5
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
    ServiceAccountDirectory,
    UserDirectory,
    UserDirectoryAdmin,
)


def _protocol_member_names(protocol: type) -> frozenset[str]:
    names: set[str] = set()
    for base in protocol.__mro__:
        if not getattr(base, "_is_protocol", False):
            continue
        try:
            names.update(_get_protocol_members(base))
        except TypeError:
            pass
    return frozenset(name for name in names if not name.startswith("_"))


@pytest.mark.parametrize(
    "protocol",
    [
        LoginProvider,
        RedirectLoginProvider,
        FormLoginProvider,
        UserDirectory,
        UserDirectoryAdmin,
        ServiceAccountDirectory,
        ApiKeyDirectory,
    ],
)
def test_frozen_member_lists_match_protocols(protocol: type) -> None:
    assert getattr(protocol, "_is_protocol", False)
    expected = _protocol_member_names(protocol)
    frozen = PROTOCOL_MEMBERS_0_5[protocol]
    assert frozen == expected, (
        f"{protocol.__name__}: frozen={sorted(frozen)} protocol={sorted(expected)}"
    )
