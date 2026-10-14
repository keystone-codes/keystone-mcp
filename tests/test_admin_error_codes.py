"""Built-in admin adapters expose stable error code constants."""

from __future__ import annotations

import pytest

from support.admin_error_codes import assert_constants_cover_ast

_FAMILIES = ("users", "service_accounts", "api_keys", "policy")


@pytest.mark.parametrize("family", _FAMILIES)
def test_error_code_constants_cover_source(family: str) -> None:
    assert_constants_cover_ast(family)
