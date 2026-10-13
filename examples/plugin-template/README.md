# Keystone-MCP plugin example

This package shows how to ship a **users directory** and a **sign-in provider** as
installable entry points, and how to keep them honest with Keystone's contract
tests.

## Rename the package

1. Pick a distribution name (`keystone-mcp-<yourname>` is recommended).
2. Rename the `keystone_plugin_example` import package under `src/`.
3. Update `pyproject.toml` (`name`, entry-point targets, and `[tool.hatch.build.targets.wheel]`).

## Implement your directory

- Read-only directories declare `capabilities = frozenset()` and implement
  `resolve_user`, `list_users`, `ping`, and `aclose`.
- `StaticFileUserDirectory` in `directory.py` loads `options["path"]` (a YAML
  list with `email`, `full_name`, `roles`, `blocked`).
- Administrative directories add `"admin"` (and optionally `"service_accounts"`
  or `"api_keys"`) to `capabilities` and implement the matching protocol
  methods (see `docs/user-directory.md` in Keystone).

## Implement your sign-in provider

- `ExampleOidcProvider` subclasses Keystone's `OidcLoginProvider` and maps
  groups from the `roles` JWT claim by default.
- `create_provider` reads OIDC settings from the provider row's `options` and
  loads the client secret with `context.secret(client_secret_env)`.

## Run contract tests

```bash
pip install -e ".[test]"
pytest
```

The template enables `-p keystone_mcp.contract_tests` via `pyproject.toml`. Your
tests subclass the contract mixins and provide the fixtures documented in
`docs/plugins.md` (`keystone_directory_factory`, `keystone_oidc_provider_factory`,
and so on).

## Wire Keystone to your plugin

**Directory**

```bash
export KEYSTONE_MCP_USERS_BACKEND=static-file
export KEYSTONE_MCP_USERS_BACKEND_CONFIG=/path/to/directory.yaml
```

The config file is a mapping passed as `options` (for this example, `path:`).

**Sign-in**

Add a provider row with `type: example-oidc` to `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`
and set `issuer`, `client_id`, and `client_secret_env` in `options`.

## Publish

See [Publishing your plugin](../../docs/plugins.md#publishing-your-plugin) in the
Keystone documentation.
