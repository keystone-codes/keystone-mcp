# 0007 — Sign-in goes through `LoginProvider`; Google is one OIDC provider

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Keystone must support several sign-in methods (OIDC tenants, Google Workspace, API
keys on a form) without baking each integration into the OAuth server or the
login HTML. Operators also need a stable callback URL for Google that matches
what is already registered in the cloud console.

## Decision

We route every sign-in method through the `LoginProvider` protocol in
`keystone_mcp.login.protocol`. Providers declare a kind — `redirect` (browser
leaves Keystone for the identity provider) or `form` (credentials on Keystone's
page). A provider proves who signed in (`LoginIdentity`); it does not see the
OAuth authorization transaction, pending-login store, users directory, or page
templates.

Generic OIDC is `OidcLoginProvider` (`keystone_mcp.login.oidc`), loaded via the
`oidc` entry point. Google is the same class with a fixed issuer and discovery
URL, registered as the `google` entry point (`create_google_provider`). When the
provider instance is named `google`, the redirect URI stays
`{KEYSTONE_MCP_BASE_URL}/login/google/callback` so existing Google OAuth client
settings keep working.

Legacy `KEYSTONE_MCP_GOOGLE_*`, `KEYSTONE_MCP_ENABLED_LOGIN_METHODS`, and
`KEYSTONE_MCP_PRIMARY_LOGIN_METHOD` remain readable as aliases into the login
providers file; they are **deprecated since 0.5.0, removed in 2.0** and log at
startup. Configuration belongs in `KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`.

## Consequences

New sign-in methods are either a new row in the YAML file (built-in types) or a
package with a `keystone_mcp.login_providers` entry point. Keystone owns CSRF,
transaction state, directory lookup, and token issuance consistently for every
provider.

Operators must maintain the providers file and register each redirect provider's
callback at `{BASE_URL}/login/<name>/callback` (Google excepted as above).

## Alternatives considered

**Hard-coded Google-only OAuth** — Blocks Okta, Entra, and Keycloak without
forking; rejected.

**Providers that read the OAuth pending transaction** — Couples sign-in to
token-endpoint details and makes testing harder; rejected.

**New callback path for Google** — Would force every deployment to re-register
OAuth clients; rejected.

## Links

- [login-providers.md](../login-providers.md), [plugins.md](../plugins.md)
- `src/keystone_mcp/login/`, `src/keystone_mcp/login/factory.py`
