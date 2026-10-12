# 0009 — Extensions are discovered only through entry points; built-ins use the same path

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Forks and companion packages need to add sign-in methods or user-directory
backends without copying Keystone's factory code or patching `pyproject.toml`
inside the main tree. Built-in implementations must follow the same discovery
rules so behaviour and tests stay aligned.

## Decision

Keystone loads plugins exclusively from
[entry points](https://packaging.python.org/en/latest/specifications/entry-points/)
declared in installed distributions:

- `keystone_mcp.login_providers` — factory
  `(LoginProviderConfig, PluginContext) -> LoginProvider`
- `keystone_mcp.user_directories` — factory
  `(PluginContext, options) -> UserDirectory`

Discovery and conflict checks live in `keystone_mcp.plugins`. Only the entry
selected in configuration is instantiated (`ep.load()` by name), not every
declared plugin.

Built-in names are registered in the main `pyproject.toml` the same way as
third-party code: `oidc`, `google`, `api_key` for login; `local`, `http` for
directories. Those names are reserved — a foreign package cannot override them.

Contract coverage ships in the `keystone_mcp.contract_tests` package (helpers
for implementers) and in the repository test suite (`tests/test_plugins.py`,
`tests/test_user_directory_protocol.py`, and related tests).

## Consequences

Operators install a wheel that declares entry points, then reference the entry
name in `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH` (`type:`) or
`KEYSTONE_MCP_USERS_BACKEND` (with optional `KEYSTONE_MCP_USERS_BACKEND_CONFIG`).

Plugin authors must validate options in the factory (raise `ValueError`) and
read secrets only through `PluginContext.secret()` — no network I/O in the
factory.

## Alternatives considered

**Import hooks or `PYTHONPATH` scanning** — Unpredictable load order and hard to
audit; rejected.

**Built-ins wired only in code, plugins via entry points** — Two paths to test
and document; rejected.

**Load all entry points at startup** — Would run untrusted factory code for
implementations the deployment does not use; rejected.

## Links

- [plugins.md](../plugins.md), [login-providers.md](../login-providers.md),
  [user-directory.md](../user-directory.md)
- `src/keystone_mcp/plugins.py`, `keystone-mcp plugins list`
