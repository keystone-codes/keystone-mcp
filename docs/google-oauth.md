# Google sign-in

Keystone-MCP asks Google who the person is, then checks that email in the users
directory. The Google Cloud project is yours. Keystone-MCP only needs the client
id, the client secret, and a redirect URI that matches the public base URL
exactly.

There is no separate setting for the redirect URI. It is always

```text
{KEYSTONE_MCP_BASE_URL}/login/google/callback
```

`KEYSTONE_MCP_BASE_URL` has no trailing slash in that address. `http://localhost:8080`
and `http://127.0.0.1:8080` are different URIs. The value registered in Google
and the value in the environment must be the same string.

## 1. Project

Open [Google Cloud Console](https://console.cloud.google.com/) and create a
project, or select the one that should own this login. The project name is
shown on the consent screen. It is not read by Keystone-MCP.

## 2. OAuth client

In that project open **Google Auth Platform → Clients** (older consoles:
**APIs & Services → Credentials**). Create an OAuth client.

| Field | Value |
|---|---|
| Application type | Web application |
| Name | Anything you will recognize. Keystone-MCP does not read it. |
| Authorized redirect URIs | `{KEYSTONE_MCP_BASE_URL}/login/google/callback` |
| Authorized JavaScript origins | The origin of that same URL, with no path: `https://mcp.example.com` or `http://localhost:8080` |

Add one redirect URI per public base URL you actually run (local and
production are two clients, or two URIs on one client). Google rejects an
`http://` redirect except for localhost.

Copy the client id and the client secret. The secret is shown once.

## 3. Consent screen

Still in Google Auth Platform, open the consent screen (Branding / Audience,
or the older **OAuth consent screen**).

- App name, user support email, and a developer contact email are required by Google.
- Scopes: `openid` and `email`. Keystone-MCP sends `scope=openid email` and refuses an id token whose email is missing or not verified. Do not add extra scopes. Keystone-MCP does not ask for them.
- Audience. **Internal** limits sign-in to your own Workspace organization. **External** in **Testing** lets only the test users you list sign in, and the consent screen says the app is unverified. **External** in **Production** is what you publish for people outside that test list. Publishing an external app may require Google's verification if you later add sensitive scopes. `openid` and `email` stay inside the basic set.

## 4. Keystone-MCP

```bash
KEYSTONE_MCP_BASE_URL=https://mcp.example.com
KEYSTONE_MCP_GOOGLE_CLIENT_ID=....apps.googleusercontent.com
KEYSTONE_MCP_GOOGLE_CLIENT_SECRET=...
KEYSTONE_MCP_ENABLED_LOGIN_METHODS=google
KEYSTONE_MCP_PRIMARY_LOGIN_METHOD=google
```

`google` must be listed in `KEYSTONE_MCP_ENABLED_LOGIN_METHODS`. Startup
refuses to run if Google is enabled and either the client id or the secret
is empty.

Google login also requires a users directory (built in by default, see
[users.md](users.md)).
After Google accepts the account, Keystone-MCP resolves the email there. An
unknown or blocked address is turned away. Create that person before they
sign in. The first administrator is covered in [users.md](users.md).

To keep the API-key form as well, set the methods to `google,api_key` and
choose which one is shown first with `KEYSTONE_MCP_PRIMARY_LOGIN_METHOD`.

## 5. Restrict the Workspace domain

Optional. Set `KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN` to the domain without `@`,
for example `example.com`. Keystone-MCP then sends Google `hd=example.com` and,
on the way back, accepts the login only when both are true: the token's
hosted-domain claim is that domain, and the email ends in `@example.com`.
Leave the variable empty to accept any verified Google account that already
exists in the directory.

## What you should see

The client opens Keystone-MCP's `/login` page, which is a consent screen
first: it names the application asking for access and the address the result
will be sent to, before anything else is shown. Only clicking **Sign in with
Google** on that page sends the browser to Google and back to
`/login/google/callback`. Keystone-MCP then finishes its own OAuth code flow
with the MCP client. The person does not paste a Google token anywhere.

A redirect mismatch from Google means the URI in the console and
`KEYSTONE_MCP_BASE_URL` disagree, including `localhost` versus `127.0.0.1`
and `http` versus `https`.
