# Google sign-in

Google is one `type: google` entry in the sign-in providers file; see
[login-providers.md](login-providers.md#google) for the file format. This
page covers the steps in Google Cloud needed to get a client id and secret.
Menu names in the Google Cloud console change over time; the steps below
avoid naming menu items where the intent is enough to find them.

Keystone never creates accounts from Google: the person signing in must
already exist in the users directory with a matching email, or sign-in fails.

## 1. A project in Google Cloud

Create (or reuse) a project in Google Cloud. The OAuth client and consent
screen below belong to this project.

## 2. Configure the consent screen

- **User type** — choose **Internal** if everyone who signs in belongs to
  your own Google Workspace organization; choose **External** otherwise (for
  example, personal Google accounts). Internal skips Google's verification
  review; External for anything beyond testing needs a support email and may
  need verification once you request scopes beyond the basic ones used here.
- **Support email** — an address your organization can answer mail at; shown
  to people on the consent screen.
- Scopes: none need adding here beyond the defaults — Keystone only requests
  `openid` and `email` at the authorization step (step 4).

## 3. Create an OAuth client

Create an OAuth client of type **Web application**. Add one **Authorized
redirect URI**:

```text
{KEYSTONE_MCP_BASE_URL}/login/google/callback
```

For example, with `KEYSTONE_MCP_BASE_URL=https://mcp.example.com`:

```text
https://mcp.example.com/login/google/callback
```

Use the exact scheme and host Keystone-MCP is reachable at — this must be an
exact match, not a prefix or a wildcard. Save the client; Google shows a
**client ID** and a **client secret**.

## 4. Scopes

Keystone-MCP asks Google for `openid` and `email` only — it does not need a
scope you add in the console; these are requested directly in the
authorization request.

## 5. Put the client id and secret where Keystone-MCP reads them

- `client_id` goes in the `google` entry of your `login-providers.yaml` (see
  [login-providers.md](login-providers.md#google) for the entry's fields).
- The client secret never goes in that file. Put it in an environment
  variable and reference that variable's name from `client_secret_env`.

## 6. Restrict sign-in to one Workspace domain (optional)

Set `allowed_domain` on the `google` entry to your Workspace domain (for
example `example.com`). Keystone-MCP then requires Google's `hd` claim and
the email's domain to match it, in addition to the person already existing
in the users directory.

## Typical errors

- **`redirect_uri_mismatch` at Google** — the URI registered on the OAuth
  client (step 3) does not exactly match
  `{KEYSTONE_MCP_BASE_URL}/login/google/callback`. Check scheme, host, and
  the absence of a trailing slash.
- **403 after a successful Google sign-in** — the email is not in the users
  directory, or it fails the `allowed_domain` check. Google authenticated the
  person; Keystone still refused them. Add the person to the users directory
  (see [users.md](users.md)) or fix `allowed_domain`.
- **503 at sign-in** — Google's discovery, token, or key endpoints were
  unreachable from Keystone-MCP when the request came in. Retry; if it
  persists, check outbound network access to `googleapis.com` from where
  Keystone-MCP runs.
