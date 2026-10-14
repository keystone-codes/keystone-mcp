"""SEC-53: policy loader error typing."""

from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import given

from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import PolicyLoadError, preflight_rbac_policy_file
from keystone_mcp.rbac.policy import PolicyContractError, parse_policy_yaml

pytestmark = [pytest.mark.security, pytest.mark.fuzz]

yaml_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=400)


@given(raw=yaml_text)
def test_parse_policy_yaml_only_contract_errors(raw: str) -> None:
    try:
        parse_policy_yaml(raw)
    except PolicyContractError:
        return
    except Exception as exc:
        raise AssertionError(f"unexpected {exc!r}") from exc


@given(raw=yaml_text)
def test_preflight_policy_maps_to_policy_load_error(tmp_path, raw: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(raw, encoding="utf-8")
    settings = Settings(rbac_mode="enforce", rbac_policy_path=str(path))
    try:
        preflight_rbac_policy_file(settings)
    except PolicyLoadError:
        return
    except OSError:
        return
    except Exception as exc:
        raise AssertionError(f"unexpected {exc!r}") from exc
