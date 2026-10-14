# Plugins

Why: [ADR 0014](adr/0014-plugin-protocols-grow-by-new-protocols.md).

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
`http_timeout_seconds`, and `secret(env_name)` (which also accepts
`<env_name>_FILE` with the same rules as built-in secrets). Fields `settings` and
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

Keystone ships executable contract tests in `keystone_mcp.contract_tests`. They
are **synchronous** pytest classes you subclass in your own test suite; they do
not require `pytest-asyncio`. Load the plugin explicitly:

```bash
pytest -p keystone_mcp.contract_tests
```

or add `pytest_plugins = ["keystone_mcp.contract_tests"]` to your `conftest.py`
(the plugin is **not** registered via `pytest11`, so it never loads twice inside
Keystone's own tree).

Install the optional extra:

```bash
pip install "keystone-mcp-gateway[contract-tests]>=0.5,<2"
```

### Fixtures you provide

| Fixture | Used by | Shape |
| --- | --- | --- |
| `keystone_directory_factory` | directory contracts | `Callable[[], Awaitable[UserDirectory]]` — each call returns a **new** directory containing exactly `CONTRACT_DATASET` |
| `keystone_unavailable_directory_factory` | availability tests (optional) | same shape; backend must be down. If omitted, those tests are skipped |
| `keystone_oidc_provider_factory` | `OidcLoginProviderContract` | `Callable[[FakeOidcIssuer], RedirectLoginProvider]` |
| `keystone_form_provider_case` | `FormLoginProviderContract` | `FormProviderCase` with async factory, valid form, and invalid samples |
| `keystone_revision_probe` | `AdminDirectoryChecks06` (optional) | `Callable[[], Awaitable[int]]` — directory revision after mutations |
| `keystone_advance_clock` | `ApiKeyDirectoryChecks06` (optional) | `Callable[[float], None]` — advance the directory clock for expiry tests |

The built-in plugin fixture `fake_oidc_issuer` supplies an in-process OIDC
provider; `keystone_oidc_provider` is derived from your factory.

### Contract classes

- Optional base classes in `keystone_mcp.user_directory.base` and
  `keystone_mcp.login.base` (inheritance is not required).
- `UserDirectoryContract` — read path (`resolve_user`, `list_users`, `ping`, …).
- `AdminDirectoryContract` — extends the read contract; requires `"admin"`.
- `ServiceAccountDirectoryContract` — requires `"service_accounts"`.
- `ApiKeyDirectoryContract` — requires `"api_keys"`.
- Optional `ApiKeyIdIndex` (see `keystone_mcp.user_directory.protocol`) lets
  Keystone reject unknown API key ids before calling your directory; without
  it, Keystone rate-limits first-time ids to 20 directory lookups per second
  (burst 50) per replica.
- `OidcLoginProviderContract` / `FormLoginProviderContract` — sign-in providers.

Opt-in **0.6.0** check classes (mix in alongside the matching base contract; they
become part of the main contract classes in 2.0):

| Class | Adds |
| --- | --- |
| `UserDirectoryChecks06` | Unavailable error codes; `list_users` excludes service accounts |
| `AdminDirectoryChecks06` | Blocked second administrator; self-demotion via `replace_roles`; e-mail normalization on mutations; invalid input raises `UsersError`; revision bump |
| `ServiceAccountDirectoryChecks06` | Unknown service account updates; invalid roles; blocked `resolve_user` |
| `ApiKeyDirectoryChecks06` | Expired keys; service-account key verification; secret suffix never listed |
| `OidcLoginProviderChecks06` | HS256 rejection, JWKS rotation, token-endpoint errors, discovery tampering, missing `code`, cross-attempt replay, e-mail normalization, wrong-issuer `LoginRejected` coverage |
| `FormLoginProviderChecks06` | Form metadata; explicit `FormProviderCase.email_field`; empty form rejected |

`FormProviderCase.email_field` names the e-mail input (default `"email"`). Set it when
your valid form uses another field name so `test_email_normalization_needs_email_field`
can run.

Helper `seed_contract_dataset(directory)` fills an admin-capable directory with
the shared `CONTRACT_DATASET` (Alice, Bob, Carol).

### Minimal example

```python
from keystone_mcp.contract_tests import UserDirectoryContract


class TestMyDirectory(UserDirectoryContract):
    @pytest.fixture
    def keystone_directory_factory(self):
        async def factory():
            directory = await build_my_directory()
            return directory

        return factory
```

## Plugin template

`examples/plugin-template/` is a complete, installable package
(`keystone-mcp-plugin-example`) with:

- `StaticFileUserDirectory` (read-only YAML list; no admin capability),
- `ExampleOidcProvider` (OIDC built on `OidcLoginProvider`),
- entry points `static-file` and `example-oidc`,
- green contract tests (`pip install -e .[test] && pytest`).

Copy the tree, rename the module, and replace the example implementations.

## What Keystone does not trust from a plugin

Keystone treats directory and login plugins as untrusted input: email addresses
are normalized before they become a token subject; role names are checked against
the active RBAC policy (unknown roles do not grant access); malformed or
contradictory directory responses fail closed rather than granting access; login
providers cannot impersonate another provider name or return service-account
subjects on human sign-in paths. See `tests/security/test_hostile_plugins.py`.

## Publishing your plugin

- Prefer distribution names `keystone-mcp-<name>` on PyPI.
- Depend on `keystone-mcp-gateway>=0.5,<2`: the plugin API is frozen until 2.0
  (see [compatibility.md#plugin-api](compatibility.md#plugin-api)).
- If your directory declares `admin`, `service_accounts`, or `api_keys`, your
  test class must inherit the matching contract class; provide
  `keystone_unavailable_directory_factory` or mark the class
  `@pytest.mark.keystone_contract_lenient(reason=...)`.
- Ship your own `CHANGELOG.md`; Keystone's compatibility promise covers the
  protocols and contract tests, not your plugin's feature set.
- You are responsible for the security of your code and for how operators
  configure secrets and access.
