"""Catalog of upstream prompts and resources published on namespace sub-servers."""

from __future__ import annotations

from dataclasses import dataclass, field

from fastmcp.resources.template import ResourceTemplate
from pydantic import AnyUrl


def _template_matches(uri_template: str, uri: str) -> bool:
    template = ResourceTemplate(uri_template=uri_template, name="", parameters={})
    return template.matches(uri) is not None


def normalize_resource_uri(uri: str) -> str:
    try:
        return str(AnyUrl(uri))
    except Exception:
        return uri


def published_uri_for_namespace(namespace: str, uri: str) -> str:
    """Namespace-inserted resource URI (private fastmcp API)."""
    from fastmcp.server.transforms.namespace import Namespace

    return Namespace(namespace)._transform_uri(uri)


@dataclass(frozen=True, slots=True)
class UpstreamPromptSpec:
    """One filtered upstream prompt ready to mount under a namespace."""

    name: str
    published_name: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class UpstreamResourceSpec:
    """One filtered upstream resource ready to mount under a namespace."""

    uri: str
    published_uri: str
    name: str
    rbac_name: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class UpstreamTemplateSpec:
    """One filtered upstream resource template ready to mount under a namespace."""

    uri_template: str
    published_uri_template: str
    name: str
    rbac_name: str
    fingerprint: str


@dataclass
class UpstreamContentCatalog:
    """Per-namespace upstream prompts and resources."""

    _prompts: dict[str, dict[str, UpstreamPromptSpec]] = field(default_factory=dict)
    _prompt_owners: dict[str, str] = field(default_factory=dict)
    _resources: dict[str, dict[str, UpstreamResourceSpec]] = field(default_factory=dict)
    _templates: dict[str, dict[str, UpstreamTemplateSpec]] = field(default_factory=dict)
    _resource_owners: dict[str, str] = field(default_factory=dict)
    _template_owners: dict[str, str] = field(default_factory=dict)

    def prompts(self, namespace: str) -> dict[str, UpstreamPromptSpec]:
        return dict(self._prompts.get(namespace, {}))

    def set_prompts(self, namespace: str, specs: dict[str, UpstreamPromptSpec]) -> None:
        previous = self._prompts.get(namespace, {})
        for spec in previous.values():
            owner = self._prompt_owners.get(spec.published_name)
            if owner == f"{namespace}:{spec.name}":
                self._prompt_owners.pop(spec.published_name, None)
        self._prompts[namespace] = dict(specs)
        for spec in specs.values():
            self._prompt_owners[spec.published_name] = f"{namespace}:{spec.name}"

    def resources(self, namespace: str) -> dict[str, UpstreamResourceSpec]:
        return dict(self._resources.get(namespace, {}))

    def set_resources(self, namespace: str, specs: dict[str, UpstreamResourceSpec]) -> None:
        previous = self._resources.get(namespace, {})
        for spec in previous.values():
            owner = self._resource_owners.get(spec.rbac_name)
            if owner == f"{namespace}:{spec.uri}":
                self._resource_owners.pop(spec.rbac_name, None)
        self._resources[namespace] = dict(specs)
        for spec in specs.values():
            self._resource_owners[spec.rbac_name] = f"{namespace}:{spec.uri}"

    def templates(self, namespace: str) -> dict[str, UpstreamTemplateSpec]:
        return dict(self._templates.get(namespace, {}))

    def set_templates(self, namespace: str, specs: dict[str, UpstreamTemplateSpec]) -> None:
        previous = self._templates.get(namespace, {})
        for spec in previous.values():
            owner = self._template_owners.get(spec.rbac_name)
            if owner == f"{namespace}:{spec.uri_template}":
                self._template_owners.pop(spec.rbac_name, None)
        self._templates[namespace] = dict(specs)
        for spec in specs.values():
            self._template_owners[spec.rbac_name] = f"{namespace}:{spec.uri_template}"

    def owner_of_published_prompt(self, published_name: str) -> str | None:
        return self._prompt_owners.get(published_name)

    def owner_of_resource_rbac(self, rbac_name: str) -> str | None:
        return self._resource_owners.get(rbac_name)

    def owner_of_template_rbac(self, rbac_name: str) -> str | None:
        return self._template_owners.get(rbac_name)

    def resolve_published_uri(self, requested_uri: str) -> str:
        """Map a client-normalized URI back to the catalog's published form."""
        normalized = normalize_resource_uri(requested_uri)
        for specs in self._resources.values():
            for spec in specs.values():
                if normalize_resource_uri(spec.published_uri) == normalized:
                    return spec.published_uri
        for specs in self._templates.values():
            for spec in specs.values():
                if _template_matches(spec.published_uri_template, requested_uri):
                    return requested_uri
                if _template_matches(spec.published_uri_template, normalized):
                    return requested_uri
        return requested_uri

    def rbac_name_for_uri(self, published_uri: str) -> str | None:
        resolved = self.resolve_published_uri(published_uri)
        for specs in self._resources.values():
            for spec in specs.values():
                if spec.published_uri == resolved:
                    return spec.rbac_name
                if normalize_resource_uri(spec.published_uri) == normalize_resource_uri(resolved):
                    return spec.rbac_name
        for specs in self._templates.values():
            for spec in specs.values():
                if _template_matches(spec.published_uri_template, resolved):
                    return spec.rbac_name
        return None

    def rbac_name_for_template_listing(self, published_uri_template: str) -> str | None:
        for specs in self._templates.values():
            for spec in specs.values():
                if spec.published_uri_template == published_uri_template:
                    return spec.rbac_name
        return None

    def rbac_names(self) -> frozenset[str]:
        names: set[str] = set()
        for by_ns in self._prompts.values():
            for spec in by_ns.values():
                names.add(spec.published_name)
        for by_ns in self._resources.values():
            for spec in by_ns.values():
                names.add(spec.rbac_name)
        for by_ns in self._templates.values():
            for spec in by_ns.values():
                names.add(spec.rbac_name)
        return frozenset(names)
