# Connect an MCP client

The server address is the base URL your operator gave you, for example
`https://mcp.example.com/` or `http://localhost:8080/` for the local demo. If
the operator changed the default path (`KEYSTONE_MCP_HTTP_PATH`), the address
has that path appended, e.g. `https://mcp.example.com/mcp/`. Every client
below registers itself with the server and then opens your browser for
sign-in — you never type a password into the client itself.

## Before you start

You need:

- The server address.
- Your email, already added to the users directory by an administrator. A
  client that reaches `/login` with an email the directory does not know
  still gets refused — sign-in and "being a known user" are two separate
  checks.
- Either a Google account or a **DEV token**, depending on which sign-in
  method the operator turned on (`KEYSTONE_MCP_ENABLED_LOGIN_METHODS`). Ask
  the operator which one applies to you.

Every sign-in goes through the same page on the server, regardless of which
client opened it. Keystone-MCP shows which application is asking and, in
bold, where it will send you back; continue only if you recognise both and
started the connection yourself.

## Claude Code

### Add the server

```bash
claude mcp add --transport http keystone https://mcp.example.com/
```

For the local demo:

```bash
claude mcp add --transport http keystone http://localhost:8080/
```

Add `--scope user` to make the server available in every project of yours,
or `--scope project` to write it to `.mcp.json` and share it with your team
through version control. Without `--scope`, the server is private to the
current project.

### Sign in

Inside a Claude Code session, run:

```text
/mcp
```

Select `keystone` — it shows **Needs authentication** — and follow the
browser prompt. From a shell, the same thing is:

```bash
claude mcp login keystone
```

`claude mcp list` shows the server's status (`Connected`, `Needs
authentication`, or `Failed to connect`).

### Sign in as someone else

Open `/mcp`, select `keystone`, choose **Clear authentication**, then
**Re-authenticate**. From a shell:

```bash
claude mcp logout keystone
claude mcp login keystone
```

## Cursor

### Add the server

Edit `~/.cursor/mcp.json` to make the server available in every project, or
`.cursor/mcp.json` in the project root to share it with your team:

```json
{ "mcpServers": { "keystone": { "url": "https://mcp.example.com/" } } }
```

For the local demo, use `"url": "http://localhost:8080/"`. Open
**Customize** in the sidebar to confirm the server loaded; the same panel
has the toggle to enable or disable it.

### Sign in

Keystone-MCP needs no client id or secret from you — Cursor discovers the
OAuth requirement itself from the server. The first time you use a
`keystone`-published tool, Cursor opens your browser to Keystone-MCP's
sign-in page: enter your email and your Google account or DEV token, then
**Authorize**.

### Sign in as someone else

Cursor does not publish a separate sign-out action for a manually added
server. Remove the `keystone` entry under **Customize** and add it again —
this drops its stored session, and Cursor runs the OAuth handoff again the
next time a tool is used.

## Claude Desktop

Claude Desktop's built-in connectors run in Anthropic's cloud, not on your
computer, so they cannot reach `http://localhost:...`. Use a custom
connector only for a public HTTPS address; use the `mcp-remote` bridge below
for a local one.

### Public HTTPS address: add a connector

1. Open **Customize > Connectors**.
2. Click **+ Add**, then **Add custom connector**.
3. Enter a name (shown in your connectors list) and the server address,
   e.g. `https://mcp.example.com/`.
4. Review the authentication Claude detected and continue.
5. Under **Authentication**, choose **Sign in now**.
6. Click **Add**, then sign in with your Google account or DEV token on the
   page that opens.

The server must be reachable over the public internet by HTTPS — a server
behind a firewall or VPN, or on `http://`, does not work here.

### Local address: use the mcp-remote bridge

Claude Desktop only launches local command-line servers, so a local
Keystone-MCP needs a small bridge, `mcp-remote` (requires Node.js 18+).

Edit the config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "keystone": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:8080/"]
    }
  }
}
```

Restart Claude Desktop. On first use, `mcp-remote` opens your browser to the
same sign-in page described above.

### Sign in as someone else

- **Connector:** open **Customize > Connectors**, remove the `keystone`
  connector, then add it again.
- **mcp-remote bridge:** quit Claude Desktop, delete `~/.mcp-auth` (where
  `mcp-remote` stores its tokens), then reopen Claude Desktop.

## Other MCP clients

Any client that speaks Streamable HTTP and OAuth 2.1 with PKCE works.
Keystone-MCP publishes `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-authorization-server` for discovery, and accepts
self-registration at `POST /register` unless the operator turned that off
(`KEYSTONE_MCP_OAUTH_DCR_ENABLED=false`). If it is off, or your client
cannot register itself, ask the operator to register it by hand — see
[Registering a client manually](environment.md#registering-a-client-manually).

### `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`

An operator who restricts return addresses with this variable needs the
exact host each client redirects back to:

| Client | Host to allow |
|---|---|
| Claude Code | `localhost` (it listens on a different local port each time; the restriction matches on host only) |
| Cursor, desktop app | `localhost` |
| Cursor, web and Background Agents | `cursor.com` |
| Claude Desktop, `mcp-remote` bridge | `localhost` |
| Claude Desktop, custom connector | `claude.ai` |

For a client not listed here, start the sign-in once with the restriction
off, then search the server log for `redirect_uri host not allowed` — it
names the exact host the client asked for.

## If sign-in does not work

| Symptom | Fix |
|---|---|
| The browser did not open | Copy the URL the client printed (Claude Code and `mcp-remote` both print "visit this URL to authorize") and open it yourself. |
| Refused after sign-in, or "unknown user" | Your email is not yet in the users directory. Ask an administrator to add it — this applies to Google and DEV-token sign-in alike. |
| Google sign-in fails with `redirect_uri_mismatch` | This is on the operator's side: the Google OAuth client's redirect URI does not match. See [google-oauth.md](google-oauth.md). |
| The client shows an old or missing tool list | Reconnect (disable, then enable, the server). Keystone-MCP does not push a live tool-list update when its upstream catalog changes in the background; see [facade.md](facade.md). |
| `http://` to a public address is refused | Use `https://`. A `production`-profile server refuses a plain-`http` address once it is reachable publicly. |
