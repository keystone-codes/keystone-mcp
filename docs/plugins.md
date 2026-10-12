# Plugins

Keystone-MCP can load **sign-in provider types** and **users directories** from
other Python packages. A plugin is declared with
[entry points](https://packaging.python.org/en/latest/specifications/entry-points/)
in its `pyproject.toml`; Keystone loads only the implementation you select in
configuration (`ep.load()` by name), not every declared entry at startup.

## What you can plug in

| Group | Purpose |
| --- | --- |
| `keystone_mcp.login_providers` | A new `type:` value in the login providers YAML file |
| `keystone_mcp.user_directories` | A new `KEYSTONE_MCP_USERS_BACKEND` name |

Built-in names (`oidc`, `google`, `api_key`, `local`, `http`) are reserved for
the Keystone distribution itself.

## Declaring entry points

```toml
[project.entry-points."keystone_mcp.login_providers"]
acme = "acme_keystone.login:create_acme_provider"

[project.entry-points."keystone_mcp.user_directories"]
memory = "acme_keystone.directory:create_memory_directory"
```

## Factory contracts

Factories live in `keystone_mcp.plugins`:

- `LoginProviderFactory(config: LoginProviderConfig, context: PluginContext) -> LoginProvider`
- `UserDirectoryFactory(context: PluginContext, options: Mapping[str, Any]) -> UserDirectory`

`PluginContext` exposes `base_url`, `deployment_profile`,
`http_timeout_seconds`, and `secret(env_name)`. Fields `settings` and
`user_resolver` are **internal — do not use** in third-party plugins.

Validate your `options` in the factory and raise `ValueError` with a clear
message; do not perform network I/O there (use `warm_up` / `ping` instead).

## Operator configuration

- **Sign-in:** set `type: <entry-point-name>` on a provider row in
  `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`.
- **Directory:** set `KEYSTONE_MCP_USERS_BACKEND` to the entry-point name; optional
  `KEYSTONE_MCP_USERS_BACKEND_CONFIG` points at a YAML file whose top-level mapping
  is passed as `options` (no inline secrets — use `*_env` and `context.secret()`).

List installed declarations (no server start, no settings read):

```bash
keystone-mcp plugins list
```

Built-in implementations are marked `(built-in)`. Name conflicts between
distributions are reported as errors with exit code 1.

## Security

A plugin runs inside Keystone with full process access. Install only packages
you trust.

## Contract tests

Added in the next change.

## Plugin template

Added in the next change.
