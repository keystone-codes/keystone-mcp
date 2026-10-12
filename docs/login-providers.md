# Sign-in providers file

Keystone lists every sign-in method in a YAML file referenced by
`KEYSTONE_MCP_LOGIN_PROVIDERS_PATH`. A person must already exist in the users
directory; Keystone never creates accounts from an identity provider.

Each redirect provider gets its own callback URL:

```text
{KEYSTONE_MCP_BASE_URL}/login/<name>/callback
```

Register that exact URI at the provider. Keystone logs each callback at startup.

## File format (`version: 1`)

| Field | Applies to | Default | Meaning |
|---|---|---|---|
| `name` | all | — | Route name (`/login/<name>`). `[a-z][a-z0-9_-]{0,31}`. |
| `type` | all | — | `oidc`, `google`, or `api_key`. |
| `title` | all | capitalised `name` | Button label (with `login_with` template). |
| `issuer` | `oidc` | — | Issuer URL exactly as published in OIDC discovery. |
| `client_id` | `oidc`, `google` | — | OAuth client id. |
| `client_secret_env` | `oidc`, `google` | — | Name of an env var holding the client secret (never put secrets in the file). |
| `allowed_domains` | `oidc` | any | Lower-case email domains allowed to sign in. |
| `scopes` | `oidc` | `openid`, `email` | Must include `openid`. |
| `hosted_domain` | `oidc` | — | Sends Google `hd` and requires matching claim. |
| `email_claim` | `oidc` | `email` | JWT claim used as email. |
| `require_email_verified` | `oidc` | `true` | Require `email_verified` (bool or `"true"`). |
| `groups_claim` | `oidc` | — | Optional claim copied into `LoginIdentity.groups` (informational). |
| `extra_authorize_params` | `oidc` | — | Extra query params (not `state`, `nonce`, PKCE, etc.). |
| `additional_issuers` | `oidc` | — | Other accepted `iss` values in the id token. |
| `token_auth_method` | `oidc` | from discovery | `client_secret_basic` or `client_secret_post`. |
| `allowed_domain` | `google` | — | Workspace domain (`hd` + email suffix). |

See [examples/login-providers.example.yaml](../examples/login-providers.example.yaml).

## Google

Use `type: google` with the same client id and secret you would previously set in
`KEYSTONE_MCP_GOOGLE_*`. Redirect URI:
`{KEYSTONE_MCP_BASE_URL}/login/google/callback`.

## Okta

Create a Web application with Authorization Code and PKCE. Issuer is usually
`https://<okta-domain>/oauth2/default` (or `https://<okta-domain>` for the org
authorization server). Scopes: `openid email`.

## Microsoft Entra ID

Register an app in the tenant. Issuer:
`https://login.microsoftonline.com/<tenant-id>/v2.0`. Add optional `email` claim
in Token configuration. Set `require_email_verified: false` and require
`allowed_domains` (Entra does not emit `email_verified`). Do not use `/common` or
`/organizations` — the issuer will not match discovery.

## Keycloak

Issuer: `https://<host>/realms/<realm>`. Confidential client, Standard flow,
valid redirect URI as above. For local Keycloak on loopback HTTP, use
`KEYSTONE_MCP_DEPLOYMENT_PROFILE=local`.

## Troubleshooting

- **Issuer mismatch** — copy the `issuer` field from
  `/.well-known/openid-configuration` into the file character-for-character.
- **Clock skew** — id tokens are rejected when server time is far from the provider.
- **Email** — enable `email` scope/claim; with `require_email_verified: false` you
  must set `allowed_domains` or `hosted_domain`, or startup refuses the file.
- **Domains** — use `allowed_domains` for Okta/Entra/Keycloak; `hosted_domain` is
  for Google Workspace (`hd`).

## Deprecated environment variables

| Legacy variable | Replacement in file |
|---|---|
| `KEYSTONE_MCP_GOOGLE_CLIENT_ID` | `client_id` on a `google` entry |
| `KEYSTONE_MCP_GOOGLE_CLIENT_SECRET` | `client_secret_env` |
| `KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN` | `allowed_domain` |
| `KEYSTONE_MCP_ENABLED_LOGIN_METHODS` | list providers in the file |
| `KEYSTONE_MCP_PRIMARY_LOGIN_METHOD` | order of entries in the file |

These variables remain readable until the next major version but log a deprecation
warning at startup.
