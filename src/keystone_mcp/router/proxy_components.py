"""Upstream proxy MCP components (prompts; resources in Y12)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

import mcp.types as mcp_types
from fastmcp.client.telemetry import client_span
from fastmcp.exceptions import ToolError
from fastmcp.prompts import Message, PromptArgument, PromptResult
from fastmcp.prompts.base import InputRequiredPromptResult
from fastmcp.server.dependencies import get_context
from fastmcp.server.providers.proxy import (
    ProxyPrompt,
    _stash_proxy_request_context,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import PrivateAttr

from keystone_mcp.identity import make_task_id, upstream_identity_headers
from keystone_mcp.identity_assertion import IDENTITY_HEADER

if TYPE_CHECKING:
    from keystone_mcp.identity_assertion import IdentityAssertionSigner
    from keystone_mcp.router.upstream import UpstreamRegistry


class UpstreamProxyPrompt(ProxyPrompt):
    """ProxyPrompt whose client carries keystone-mcp's upstream auth and identity."""

    _namespace: str = PrivateAttr()
    _registry: "UpstreamRegistry" = PrivateAttr()
    _backend_name: str = PrivateAttr()
    _identity_signer: IdentityAssertionSigner | None = PrivateAttr(default=None)
    _extra_headers: dict[str, str] = PrivateAttr(default_factory=dict)
    _tool_timeout: float = PrivateAttr(default=180.0)
    _rbac_mode: str = PrivateAttr(default="off")
    _transport: Literal["http", "stdio"] = PrivateAttr(default="http")

    @classmethod
    def from_upstream_prompt(
        cls,
        *,
        registry: "UpstreamRegistry",
        namespace: str,
        mcp_prompt: mcp_types.Prompt,
        backend_name: str,
        identity_signer: IdentityAssertionSigner | None,
        extra_headers: dict[str, str],
        tool_timeout: float,
        rbac_mode: str,
        transport: Literal["http", "stdio"],
    ) -> UpstreamProxyPrompt:
        arguments = [
            PromptArgument(
                name=arg.name,
                description=arg.description,
                required=arg.required or False,
            )
            for arg in mcp_prompt.arguments or []
        ]

        async def _unused_client_factory() -> Any:
            raise RuntimeError("UpstreamProxyPrompt uses _get_client(), not client_factory")

        prompt = cls(
            client_factory=_unused_client_factory,
            name=mcp_prompt.name,
            title=mcp_prompt.title,
            description=mcp_prompt.description,
            arguments=arguments,
            icons=mcp_prompt.icons,
            meta=mcp_prompt.meta,
            tags=(),
        )
        prompt._namespace = namespace
        prompt._registry = registry
        prompt._backend_name = backend_name
        prompt._identity_signer = identity_signer
        prompt._extra_headers = dict(extra_headers)
        prompt._tool_timeout = tool_timeout
        prompt._rbac_mode = rbac_mode
        prompt._transport = transport
        return prompt

    async def _get_client(self):
        from keystone_mcp.identity import resolve_verified_identity

        identity = resolve_verified_identity()
        if identity is None:
            raise ToolError("no verified identity")

        headers = {**self._extra_headers}
        if self._identity_signer is not None and self._transport == "http":
            token = self._identity_signer.sign(
                identity=identity,
                task_id=make_task_id(
                    identity,
                    self._backend_name,
                    {},
                    namespace=self._namespace,
                ),
                mcp_method="prompts/get",
                mcp_target=self._backend_name,
                timeout_seconds=self._tool_timeout,
                rbac_mode=self._rbac_mode,
            )
            headers[IDENTITY_HEADER] = token
        if self._transport == "http":
            headers.update(upstream_identity_headers(identity))

        from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError

        try:
            return self._registry.connection(self._namespace).call_client(
                headers=headers,
                timeout=self._tool_timeout,
            )
        except UpstreamProcessUnavailableError:
            raise ToolError(f"upstream {self._namespace} is unavailable") from None

    async def render(self, arguments: dict[str, Any]) -> PromptResult:  # type: ignore[override]
        """Render via the upstream without forwarding the client's request ``_meta``."""
        backend_name = self._backend_name or self.name
        with client_span(
            f"prompts/get {backend_name}",
            "prompts/get",
            backend_name,
            prompt_name=backend_name,
        ) as span:
            span.set_attribute("fastmcp.provider.type", "UpstreamProxyPrompt")
            client = await self._get_client()
            ctx = get_context()
            async with client:
                _stash_proxy_request_context(client, ctx)
                if client.protocol_version in MODERN_PROTOCOL_VERSIONS:
                    from keystone_mcp.router.upstream_call import call_upstream_prompt_modern

                    raw = await call_upstream_prompt_modern(
                        client,
                        backend_name,
                        arguments,
                        input_responses=ctx.input_responses if ctx else None,
                        request_state=ctx.request_state if ctx else None,
                    )
                    if isinstance(raw, mcp_types.InputRequiredResult):
                        return InputRequiredPromptResult(raw)
                    result = raw
                else:
                    result = await client.get_prompt(backend_name, arguments, meta=None)
            messages = [Message(content=m.content, role=m.role) for m in result.messages]
            return PromptResult(
                messages=messages,
                description=result.description,
                meta=result.meta,
            )
