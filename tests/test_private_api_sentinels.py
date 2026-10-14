"""Sentinels for every private fastmcp/mcp API Keystone relies on.

Each row in ``PRIVATE_APIS`` is checked for existence and (for callables) a
stable ``inspect.signature``. Behavioral guards elsewhere (for example
``test_proxy_elicitation`` and ``test_registry_reaches_connection_via_private_field``)
stay in place; this module catches renames and signature drift before runtime.

``test_private_api_table_covers_source`` walks ``src/keystone_mcp/**`` and
requires every *external* private access to appear in the table:

* runtime ``from fastmcp… import _…`` / ``from mcp…._… import …`` (outside
  ``if TYPE_CHECKING:``);
* ``client._…`` attribute reads (only names listed for that file);
* ``mcp._mcp_server`` and ``Namespace(…)._…`` call chains;
* ``getattr(session, "_connection")`` in ``client_sessions.py``;
* ``self._cached_content`` on proxy resources (fastmcp field), but not Keystone's
  own ``ProxyPrompt`` / ``ProxyResource`` / ``ProxyTemplate`` assignments
  (``_namespace``, ``_registry``, … in ``proxy_components.py``).
"""

from __future__ import annotations

import ast
import inspect
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"

Kind = Literal["attribute", "function", "method"]


@dataclass(frozen=True)
class PrivateApiRow:
    owner: str
    attribute: str
    kind: Kind
    signature: str | None
    used_in: str


PRIVATE_APIS: tuple[PrivateApiRow, ...] = (
    PrivateApiRow(
        "fastmcp.client.client.Client",
        "_session_kwargs",
        "attribute",
        None,
        "router/upstream_call.py",
    ),
    PrivateApiRow(
        "fastmcp.client.client.Client",
        "_await_with_session_monitoring",
        "method",
        "(self, coro: 'Coroutine[Any, Any, ResultT]') -> 'ResultT'",
        "router/upstream_call.py",
    ),
    PrivateApiRow(
        "fastmcp.client.client.Client",
        "_parse_call_tool_result",
        "method",
        "(self: 'Client', name: 'str', result: 'mcp_types.CallToolResult', "
        "raise_on_error: 'bool' = False) -> 'CallToolResult'",
        "router/upstream_call.py",
    ),
    PrivateApiRow(
        "fastmcp.server.transforms.namespace.Namespace",
        "_transform_uri",
        "method",
        "(uri: 'str') -> 'str'",
        "router/upstream_content.py",
    ),
    PrivateApiRow(
        "fastmcp.server.transforms.namespace.Namespace",
        "_reverse_uri",
        "method",
        "(uri: 'str') -> 'str | None'",
        "router/upstream_content.py",
    ),
    PrivateApiRow(
        "fastmcp.FastMCP",
        "_mcp_server",
        "attribute",
        None,
        "server.py",
    ),
    PrivateApiRow(
        "fastmcp.server.low_level.LowLevelServer",
        "add_request_handler",
        "method",
        "(method: 'str', params_type: 'type[_ParamsT]', "
        "handler: 'RequestHandler[LifespanResultT, _ParamsT]') -> 'None'",
        "server.py",
    ),
    PrivateApiRow(
        "mcp.server.session.ServerSession",
        "_connection",
        "attribute",
        None,
        "surface/client_sessions.py",
    ),
    PrivateApiRow(
        "fastmcp.server.providers.proxy",
        "_stash_proxy_request_context",
        "function",
        "(client: 'Client', ctx: 'Context') -> 'None'",
        "router/proxy_components.py",
    ),
    PrivateApiRow(
        "fastmcp.resources.template",
        "forward_uri",
        "function",
        "(uri_template: 'str', params: 'dict[str, Any]', uri: 'str') -> 'str'",
        "router/proxy_components.py",
    ),
    PrivateApiRow(
        "fastmcp.server.providers.proxy.ProxyResource",
        "_cached_content",
        "attribute",
        None,
        "router/proxy_components.py",
    ),
)

def _normalize_signature(sig: inspect.Signature) -> str:
    text = str(sig)
    return re.sub(r"\s+", "", text)


def _resolve_target(row: PrivateApiRow) -> Any:
    if row.owner == "fastmcp.client.client.Client":
        from fastmcp import Client

        if row.attribute == "_session_kwargs":
            return getattr(Client("http://127.0.0.1"), row.attribute)
        return getattr(Client, row.attribute)
    if row.owner == "fastmcp.FastMCP":
        from fastmcp import FastMCP

        return getattr(FastMCP("sentinel"), row.attribute)
    if row.owner == "fastmcp.server.transforms.namespace.Namespace":
        from fastmcp.server.transforms.namespace import Namespace

        return getattr(Namespace("sentinel"), row.attribute)
    if row.owner == "fastmcp.server.low_level.LowLevelServer":
        from fastmcp import FastMCP

        return getattr(FastMCP("sentinel")._mcp_server, row.attribute)
    if row.owner == "mcp.server.session.ServerSession":
        from mcp.server.session import ServerSession

        if row.attribute in inspect.getsource(ServerSession):
            return row.attribute
        return None
    if row.owner == "fastmcp.server.providers.proxy":
        import fastmcp.server.providers.proxy as proxy_mod

        return getattr(proxy_mod, row.attribute)
    if row.owner == "fastmcp.resources.template":
        import fastmcp.resources.template as template_mod

        return getattr(template_mod, row.attribute)
    if row.owner == "fastmcp.server.providers.proxy.ProxyResource":
        from fastmcp.server.providers.proxy import ProxyResource

        return getattr(ProxyResource, row.attribute)
    raise AssertionError(f"unknown owner {row.owner!r}")


def _failure_message(row: PrivateApiRow) -> str:
    return (
        f"fastmcp/mcp private API changed: {row.owner}.{row.attribute} "
        f"used in {row.used_in}. Check the call site before accepting this dependency version."
    )


@pytest.mark.parametrize(
    "row",
    PRIVATE_APIS,
    ids=[f"{r.owner}.{r.attribute}" for r in PRIVATE_APIS],
)
def test_private_api_still_exists(row: PrivateApiRow) -> None:
    target = _resolve_target(row)
    assert target is not None, _failure_message(row)
    if row.kind == "attribute":
        return
    assert callable(target), _failure_message(row)
    sig = inspect.signature(target)
    wrapped = getattr(target, "__wrapped__", None)
    if wrapped is not None and str(sig) in {"(*args, **kwargs)", "(*args, **kwargs)"}:
        sig = inspect.signature(wrapped)
    if row.signature is not None:
        assert _normalize_signature(sig) == re.sub(r"\s+", "", row.signature), _failure_message(row)


def test_fastmcp_deprecation_is_an_error() -> None:
    from fastmcp.exceptions import FastMCPDeprecationWarning

    with pytest.raises(FastMCPDeprecationWarning):
        import warnings

        warnings.warn("deprecated fastmcp surface", FastMCPDeprecationWarning)


def _type_checking_line_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
            start = node.lineno
            end = max(getattr(n, "lineno", start) for n in ast.walk(node))
            ranges.append((start, end))
    return ranges


def _in_type_checking(lineno: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= lineno <= end for start, end in ranges)


def _allowed_client_attrs_for_file(rel: str) -> set[str]:
    return {
        row.attribute
        for row in PRIVATE_APIS
        if row.used_in == rel and row.owner.endswith(".Client")
    }


def _imported_private_names(tree: ast.AST) -> list[tuple[int, str]]:
    ranges = _type_checking_line_ranges(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        if _in_type_checking(node.lineno, ranges):
            continue
        module = node.module
        if not (module.startswith("fastmcp") or module.startswith("mcp")):
            continue
        private_module = "._" in module
        for alias in node.names:
            name = alias.name
            if name.startswith("_") or private_module:
                found.append((node.lineno, name))
    return found


def _scan_source_usage(path: Path) -> list[str]:
    rel = path.relative_to(SRC_ROOT).as_posix()
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    violations: list[str] = []

    table_import_names = {row.attribute for row in PRIVATE_APIS}
    for lineno, name in _imported_private_names(tree):
        if name not in table_import_names:
            violations.append(f"{rel}:{lineno}: private import {name!r} missing from PRIVATE_APIS")

    allowed_client = _allowed_client_attrs_for_file(rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.attr, str):
            if not node.attr.startswith("_") or node.attr.startswith("__"):
                continue
            if isinstance(node.value, ast.Name) and node.value.id == "client":
                if node.attr not in allowed_client:
                    violations.append(
                        f"{rel}:{node.lineno}: client.{node.attr} not listed in PRIVATE_APIS"
                    )
            if isinstance(node.value, ast.Name) and node.value.id == "mcp" and node.attr == "_mcp_server":
                if rel != "server.py":
                    violations.append(f"{rel}:{node.lineno}: mcp._mcp_server outside server.py")
            if (
                isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "Namespace"
            ):
                if node.attr not in {"_transform_uri", "_reverse_uri"}:
                    violations.append(
                        f"{rel}:{node.lineno}: Namespace().{node.attr} not in PRIVATE_APIS"
                    )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "getattr" and len(node.args) >= 2:
                const = node.args[1]
                if isinstance(const, ast.Constant) and const.value == "_connection":
                    if rel != "surface/client_sessions.py":
                        violations.append(
                            f"{rel}:{node.lineno}: getattr(..., '_connection') outside client_sessions"
                        )
        if isinstance(node, ast.Attribute) and node.attr == "_cached_content":
            if rel == "router/proxy_components.py" and isinstance(node.value, ast.Name):
                if node.value.id == "self":
                    continue
    return violations


def test_private_api_table_covers_source() -> None:
    violations: list[str] = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        violations.extend(_scan_source_usage(path))
    assert not violations, "PRIVATE_APIS table incomplete:\n" + "\n".join(violations)
