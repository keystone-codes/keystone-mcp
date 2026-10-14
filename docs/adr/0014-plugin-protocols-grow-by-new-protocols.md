# 0014 — Plugin protocols grow by new protocols, not new members

## Status

Accepted (Keystone-MCP 0.6.0)

## Context

Keystone promised in 0.5.0 that login and user-directory protocols stay stable
until 2.0. Runtime `isinstance` checks against `@runtime_checkable` protocols
require every protocol member, including methods added with a default
implementation in the protocol body — plugins that do not inherit the protocol
class never receive those defaults. Contract tests also allowed a directory to
declare `"admin"` while the test class only inherited `UserDirectoryContract`.

## Decision

Existing 0.5 protocol classes do not gain members before 2.0. New capability
for plugins is a new optional protocol (and a new `capabilities` value for
directories). Keystone validates plugins with frozen 0.5 member lists
(`PROTOCOL_MEMBERS_0_5`), not `isinstance`. Optional base classes in
`keystone_mcp.login.base` and `keystone_mcp.user_directory.base` may add
defaults for future optional protocols; inheritance is optional. A frozen
reference plugin under `tests/data/plugin_0_5/` must keep working until 2.0.
Contract tests require matching contract classes for declared capabilities and
mandatory availability fixtures, with opt-out via
`keystone_contract_lenient(reason=…)`.

## Consequences

New directory or login features ship as new protocols and documentation, not
silent protocol edits. Plugin authors can depend on `keystone-mcp-gateway>=0.5,<2`.
Operators may see stricter YAML backend config (secret-like keys rejected in nested
structures).

## Alternatives considered

- Default methods on existing protocols — rejected: breaks non-subclassing plugins.
- Drop the freeze promise — rejected: already published in 0.5.0 docs.
