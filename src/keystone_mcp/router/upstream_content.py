"""Catalog of upstream prompts (and later resources) published on namespace sub-servers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class UpstreamPromptSpec:
    """One filtered upstream prompt ready to mount under a namespace."""

    name: str
    published_name: str
    fingerprint: str


@dataclass
class UpstreamContentCatalog:
    """Per-namespace upstream prompts; resources are added in Y12."""

    _prompts: dict[str, dict[str, UpstreamPromptSpec]] = field(default_factory=dict)
    _prompt_owners: dict[str, str] = field(default_factory=dict)

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

    def owner_of_published_prompt(self, published_name: str) -> str | None:
        return self._prompt_owners.get(published_name)

    def rbac_names(self) -> frozenset[str]:
        names: set[str] = set()
        for by_ns in self._prompts.values():
            for spec in by_ns.values():
                names.add(spec.published_name)
        return frozenset(names)
