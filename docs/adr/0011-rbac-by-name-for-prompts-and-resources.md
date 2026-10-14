# 0011 — Prompts and resources are authorised by name with the tool patterns

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Upstream MCP servers expose prompts alongside tools. Keystone already namespaces
and RBAC-filters tools with `<namespace>_<name>` and the role `allow` patterns
in the policy file. Prompts must follow the same operator model so policy does
not need a second vocabulary.

## Decision

`RbacMiddleware` (`keystone_mcp.router.rbac_middleware`) applies the same
policy engine to prompts as to tools:

- `on_list_prompts` filters the catalog with `policy.allows(roles, prompt.name)`
  after identity and role resolution.
- `on_get_prompt` denies with `PromptError` when the named prompt is not allowed.

Published prompt names are already `<namespace>_<upstream prompt name>` (see
[facade.md](../facade.md#prompts-and-resources)). Allow patterns in
`config/rbac-policy.yaml` therefore use the same globs as for tools (`SYNC`,
`CONTINUATION`, and the rest) — the policy file format does not gain a prompts
section.

**Upstream resources and resource templates** use the same allow patterns as
tools. Published URIs carry the upstream namespace (`scheme://<namespace>/…`);
RBAC checks `<namespace>_<resource.name>` for static resources and templates
(the policy file still has no separate resources section). `RbacMiddleware`
filters `resources/list` and `resources/templates/list` with
`policy.allows(roles, rbac_name)`; `resources/read` denies unknown URIs that
do not match a published resource or template. Keystone does not implement
`resources/subscribe` and does not publish `notifications/resources/updated`.

## Consequences

Operators who already maintain tool allow patterns do not re-learn policy for
prompts. A prompt denied by policy disappears from `prompts/list` in enforce
mode, matching list-tools behaviour.

Unknown or disallowed prompt names fail closed on `prompts/get`.

## Amendment (0.6.0)

Keystone-MCP publishes an upstream resource or resource template only when its
URI (template) starts with `scheme://`; others are skipped with a warning and
counted in `keystone_mcp_upstream_items_rejected_total`. `resources/read` is
checked against the resources and templates of the namespace the URI belongs
to (`scheme://<namespace>/…`). When the URI matches more than one of them,
every matching RBAC name must be allowed.

An upstream resource or template whose RBAC name (`<namespace>_<name>`) equals
a published tool or prompt name from the same upstream is not published, so one
policy rule cannot grant both by accident (`reason="rbac_name_collision"`).

## Alternatives considered

**Separate `prompts:` block in the policy file** — More YAML for operators and
risk of tools and prompts diverging; rejected.

**Pass-through without RBAC** — Would expose upstream prompts to any signed-in
role; rejected.

## Links

- [facade.md](../facade.md#what-passes-through-the-door),
  [rbac-policy-format.md](../rbac-policy-format.md)
- `src/keystone_mcp/router/rbac_middleware.py`
