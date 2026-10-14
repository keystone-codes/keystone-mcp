"""SEC-52: upstream registry validation properties."""

from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import given

from keystone_mcp.upstream_registry.load import parse_upstream_entries
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import validate_upstream_registry

pytestmark = [pytest.mark.security, pytest.mark.fuzz]

_POLICY = UpstreamSecurityPolicy(allow_insecure_http=True, egress_allow_private=True)

json_value = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=8), children, max_size=5),
    max_leaves=30,
)


@given(document=json_value)
def test_validate_upstream_registry_never_raises(document) -> None:
    if not isinstance(document, dict):
        document = {"upstreams": document}
    try:
        validate_upstream_registry(document, policy=_POLICY)
    except Exception as exc:
        raise AssertionError(f"validate_upstream_registry raised {exc!r}") from exc


@given(entries=st.lists(st.dictionaries(st.text(max_size=10), json_value, max_size=8), max_size=5))
def test_parse_upstream_entries_only_value_error(entries) -> None:
    try:
        parse_upstream_entries(entries, policy=_POLICY, check_environment=False)
    except ValueError:
        return
    except TypeError:
        return
    except Exception as exc:
        raise AssertionError(f"unexpected exception {exc!r}") from exc
