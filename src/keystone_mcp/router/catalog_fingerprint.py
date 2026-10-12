"""Stable fingerprints for published upstream tool routes."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from keystone_mcp.router.registry import Param


def params_fingerprint(params: list[Param]) -> str:
    """Fingerprint of Param fields that affect the published tool signature."""
    payload: list[dict[str, Any]] = []
    for param in sorted(params, key=lambda p: p.name):
        py_name = getattr(param.type, "__name__", repr(param.type))
        payload.append(
            {
                "name": param.name,
                "type": py_name,
                "required": param.required,
                "allows_null": param.allows_null,
                "description": param.description or "",
            }
        )
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def tool_fingerprint(
    *,
    route_name: str,
    upstream_tool: str,
    description: str,
    params: list[Param],
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
    title: str | None = None,
    annotations: dict[str, Any] | None = None,
) -> str:
    """One mounted upstream tool after filters, strip_prefix, and schema patches.

    ``input_schema``/``output_schema``/``title``/``annotations`` (P07) are the
    upstream's own raw values, published verbatim; each is folded into the
    fingerprint only when non-empty, so a caller that still only has
    ``params`` (no schema -- the pre-P07 call shape) gets exactly the old
    fingerprint and an unrelated change there never looks "updated".
    """
    body: dict[str, Any] = {
        "route_name": route_name,
        "upstream_tool": upstream_tool,
        "description": description,
        "params": params_fingerprint(params),
    }
    if input_schema:
        body["input_schema"] = json.dumps(input_schema, sort_keys=True, separators=(",", ":"))
    if output_schema:
        body["output_schema"] = json.dumps(output_schema, sort_keys=True, separators=(",", ":"))
    if title:
        body["title"] = title
    if annotations:
        body["annotations"] = json.dumps(annotations, sort_keys=True, separators=(",", ":"))
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def prompt_fingerprint(
    *,
    name: str,
    title: str | None,
    description: str | None,
    arguments: list[dict[str, Any]],
) -> str:
    """Stable fingerprint for one upstream prompt (Y06)."""
    payload = {
        "name": name,
        "title": title or "",
        "description": description or "",
        "arguments": arguments,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def resource_fingerprint(
    *,
    uri: str,
    name: str,
    title: str | None,
    description: str | None,
    mime_type: str | None,
) -> str:
    """Stable fingerprint for one upstream resource (Y12)."""
    payload = {
        "uri": uri,
        "name": name,
        "title": title or "",
        "description": description or "",
        "mime_type": mime_type or "",
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def template_fingerprint(
    *,
    uri_template: str,
    name: str,
    title: str | None,
    description: str | None,
    mime_type: str | None,
) -> str:
    """Stable fingerprint for one upstream resource template (Y12)."""
    payload = {
        "uri_template": uri_template,
        "name": name,
        "title": title or "",
        "description": description or "",
        "mime_type": mime_type or "",
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
