"""Upstream proxy MCP components (prompts and resources)."""

from __future__ import annotations

import base64
import contextvars
from typing import TYPE_CHECKING, Any, Literal

import mcp.types as mcp_types
from fastmcp.client.telemetry import client_span
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.prompts import Message, PromptArgument, PromptResult
from fastmcp.prompts.base import InputRequiredPromptResult
from fastmcp.resources.base import InputRequiredResourceResult, ResourceContent, ResourceResult
from fastmcp.resources.template import forward_uri
from fastmcp.server.dependencies import get_context
from fastmcp.server.providers.proxy import (
    ProxyPrompt,
    ProxyResource,
    ProxyTemplate,
    _forwardable_server_meta,
    _stash_proxy_request_context,
)
from mcp_types import BlobResourceContents, TextResourceContents
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import PrivateAttr

from keystone_mcp.identity import make_task_id, upstream_identity_headers
from keystone_mcp.identity_assertion import IDENTITY_HEADER, IDENTITY_META_KEY

if TYPE_CHECKING:
    from fastmcp.server.context import Context

    from keystone_mcp.identity_assertion import IdentityAssertionSigner
    from keystone_mcp.router.upstream import UpstreamRegistry

_template_read_backend_uri: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_template_read_backend_uri",
    default=None,
)


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
        call_meta: dict[str, str] | None = None
        if self._identity_signer is not None:
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
            if self._transport == "http":
                headers[IDENTITY_HEADER] = token
            else:
                call_meta = {IDENTITY_META_KEY: token}
        if self._transport == "http":
            headers.update(upstream_identity_headers(identity))

        from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError

        try:
            client = self._registry.connection(self._namespace).call_client(
                headers=headers,
                timeout=self._tool_timeout,
            )
        except UpstreamProcessUnavailableError:
            raise ToolError(f"upstream {self._namespace} is unavailable") from None
        return client, call_meta

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
            client, call_meta = await self._get_client()
            ctx = get_context()
            async with client:
                _stash_proxy_request_context(client, ctx)
                if client.protocol_version in MODERN_PROTOCOL_VERSIONS:
                    from keystone_mcp.router.upstream_call import call_upstream_prompt_modern

                    raw = await call_upstream_prompt_modern(
                        client,
                        backend_name,
                        arguments,
                        meta=call_meta,
                        input_responses=ctx.input_responses if ctx else None,
                        request_state=ctx.request_state if ctx else None,
                    )
                    if isinstance(raw, mcp_types.InputRequiredResult):
                        return InputRequiredPromptResult(raw)
                    result = raw
                else:
                    result = await client.get_prompt(backend_name, arguments, meta=call_meta)
            messages = [Message(content=m.content, role=m.role) for m in result.messages]
            return PromptResult(
                messages=messages,
                description=result.description,
                meta=result.meta,
            )


def _resource_result_from_read(
    result: mcp_types.ReadResourceResult,
    *,
    backend_uri: str,
) -> ResourceResult:
    if not result.contents:
        raise ResourceError(f"Remote server returned empty content for {backend_uri}")
    contents: list[ResourceContent] = []
    for item in result.contents:
        if isinstance(item, TextResourceContents):
            contents.append(
                ResourceContent(
                    content=item.text,
                    mime_type=item.mime_type,
                    meta=item.meta,
                )
            )
        elif isinstance(item, BlobResourceContents):
            contents.append(
                ResourceContent(
                    content=base64.b64decode(item.blob),
                    mime_type=item.mime_type,
                    meta=item.meta,
                )
            )
        else:
            raise ResourceError(f"Unsupported content type: {type(item)}")
    return ResourceResult(contents=contents, meta=_forwardable_server_meta(result.meta) or None)


class _UpstreamProxyClientMixin:
    _namespace: str
    _registry: "UpstreamRegistry"
    _backend_uri: str
    _identity_signer: IdentityAssertionSigner | None
    _extra_headers: dict[str, str]
    _tool_timeout: float
    _rbac_mode: str
    _transport: Literal["http", "stdio"]
    _upstream_name: str

    async def _get_client(self):
        from keystone_mcp.identity import resolve_verified_identity

        identity = resolve_verified_identity()
        if identity is None:
            raise ToolError("no verified identity")

        mcp_target = _template_read_backend_uri.get() or self._backend_uri
        headers = {**self._extra_headers}
        call_meta: dict[str, str] | None = None
        if self._identity_signer is not None:
            token = self._identity_signer.sign(
                identity=identity,
                task_id=make_task_id(
                    identity,
                    self._upstream_name,
                    {},
                    namespace=self._namespace,
                ),
                mcp_method="resources/read",
                mcp_target=mcp_target,
                timeout_seconds=self._tool_timeout,
                rbac_mode=self._rbac_mode,
            )
            if self._transport == "http":
                headers[IDENTITY_HEADER] = token
            else:
                call_meta = {IDENTITY_META_KEY: token}
        if self._transport == "http":
            headers.update(upstream_identity_headers(identity))

        from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError

        try:
            client = self._registry.connection(self._namespace).call_client(
                headers=headers,
                timeout=self._tool_timeout,
            )
        except UpstreamProcessUnavailableError:
            raise ToolError(f"upstream {self._namespace} is unavailable") from None
        return client, call_meta


class UpstreamProxyResource(_UpstreamProxyClientMixin, ProxyResource):
    """ProxyResource whose client carries keystone-mcp's upstream auth and identity."""

    @classmethod
    def from_upstream_resource(
        cls,
        *,
        registry: "UpstreamRegistry",
        namespace: str,
        upstream_name: str,
        mcp_resource: mcp_types.Resource,
        backend_uri: str,
        identity_signer: IdentityAssertionSigner | None,
        extra_headers: dict[str, str],
        tool_timeout: float,
        rbac_mode: str,
        transport: Literal["http", "stdio"],
    ) -> UpstreamProxyResource:
        async def _unused_client_factory() -> Any:
            raise RuntimeError("UpstreamProxyResource uses _get_client(), not client_factory")

        resource = cls(
            client_factory=_unused_client_factory,
            uri=mcp_resource.uri,
            name=mcp_resource.name,
            title=mcp_resource.title,
            description=mcp_resource.description,
            mime_type=mcp_resource.mime_type or "text/plain",
            icons=mcp_resource.icons,
            meta=mcp_resource.meta,
            tags=(),
        )
        resource._namespace = namespace
        resource._registry = registry
        resource._backend_uri = backend_uri
        resource._upstream_name = upstream_name
        resource._identity_signer = identity_signer
        resource._extra_headers = dict(extra_headers)
        resource._tool_timeout = tool_timeout
        resource._rbac_mode = rbac_mode
        resource._transport = transport
        return resource

    async def read(self) -> ResourceResult:  # type: ignore[override]
        if self._cached_content is not None:
            return self._cached_content

        backend_uri = self._backend_uri
        with client_span(
            "resources/read",
            "resources/read",
            backend_uri,
            resource_uri=backend_uri,
        ) as span:
            span.set_attribute("fastmcp.provider.type", "UpstreamProxyResource")
            client, call_meta = await self._get_client()
            ctx = get_context()
            async with client:
                _stash_proxy_request_context(client, ctx)
                from keystone_mcp.router.upstream_call import call_upstream_resource_read

                result = await call_upstream_resource_read(
                    client,
                    backend_uri,
                    meta=call_meta,
                    input_responses=ctx.input_responses if ctx else None,
                    request_state=ctx.request_state if ctx else None,
                )
            if isinstance(result, mcp_types.InputRequiredResult):
                return InputRequiredResourceResult(result)
            return _resource_result_from_read(result, backend_uri=backend_uri)


class UpstreamProxyTemplate(_UpstreamProxyClientMixin, ProxyTemplate):
    """ProxyTemplate whose client carries keystone-mcp's upstream auth and identity."""

    _backend_uri_template: str = PrivateAttr()

    @classmethod
    def from_upstream_template(
        cls,
        *,
        registry: "UpstreamRegistry",
        namespace: str,
        upstream_name: str,
        mcp_template: mcp_types.ResourceTemplate,
        backend_uri_template: str,
        identity_signer: IdentityAssertionSigner | None,
        extra_headers: dict[str, str],
        tool_timeout: float,
        rbac_mode: str,
        transport: Literal["http", "stdio"],
    ) -> UpstreamProxyTemplate:
        async def _unused_client_factory() -> Any:
            raise RuntimeError("UpstreamProxyTemplate uses _get_client(), not client_factory")

        template = cls(
            client_factory=_unused_client_factory,
            uri_template=mcp_template.uri_template,
            name=mcp_template.name,
            title=mcp_template.title,
            description=mcp_template.description,
            mime_type=mcp_template.mime_type or "text/plain",
            icons=mcp_template.icons,
            meta=mcp_template.meta,
            tags=(),
            parameters={},
        )
        template._namespace = namespace
        template._registry = registry
        template._backend_uri_template = backend_uri_template
        template._backend_uri = backend_uri_template
        template._upstream_name = upstream_name
        template._identity_signer = identity_signer
        template._extra_headers = dict(extra_headers)
        template._tool_timeout = tool_timeout
        template._rbac_mode = rbac_mode
        template._transport = transport
        return template

    async def create_resource(
        self,
        uri: str,
        params: dict[str, Any],
        context: "Context | None" = None,
    ) -> ProxyResource:
        backend_template = self._backend_uri_template
        parameterized_uri = forward_uri(backend_template, params, uri)
        token = _template_read_backend_uri.set(parameterized_uri)
        try:
            client, call_meta = await self._get_client()
            ctx = context or get_context()
            async with client:
                _stash_proxy_request_context(client, ctx)
                from keystone_mcp.router.upstream_call import call_upstream_resource_read

                result = await call_upstream_resource_read(
                    client,
                    parameterized_uri,
                    meta=call_meta,
                    input_responses=ctx.input_responses if ctx else None,
                    request_state=ctx.request_state if ctx else None,
                )
        finally:
            _template_read_backend_uri.reset(token)

        if isinstance(result, mcp_types.InputRequiredResult):
            return ProxyResource(
                client_factory=lambda: client,  # unused; content cached
                uri=uri,
                name=self.name,
                title=self.title,
                description=self.description,
                mime_type=self.mime_type or "text/plain",
                icons=self.icons,
                meta=self.meta,
                tags=(),
                _cached_content=InputRequiredResourceResult(result),
            )

        cached = _resource_result_from_read(result, backend_uri=parameterized_uri)
        return ProxyResource(
            client_factory=lambda: client,
            uri=uri,
            name=self.name,
            title=self.title,
            description=self.description,
            mime_type=self.mime_type or "text/plain",
            icons=self.icons,
            meta=self.meta,
            tags=(),
            _cached_content=cached,
        )
