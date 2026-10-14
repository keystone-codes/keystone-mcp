# Connect an MCP client

The server address is the base URL your operator gave you, for example
`https://mcp.example.com/` or `http://localhost:8080/` for the local demo. If
the operator changed the default path (`KEYSTONE_MCP_HTTP_PATH`), the address
has that path appended, e.g. `https://mcp.example.com/mcp/`. Every client
below registers itself with the server and then opens your browser for
sign-in — you never type a password into the client itself.

## Tested clients

Cell values: `yes`, `no`, `n/a` (the client does not support this), or `—`
(not checked this release). Use a footnote when behaviour differs from the
norm. Column **How**: `manual (stage)` or `CI`.

| Client | Version | MCP protocol | Sign-in | Token refresh | Tools | `list_changed` | Progress | Cancel | Elicitation | Checked with Keystone-MCP | Date | How |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Claude Code | 2.1.x | — | — | — | — | — | — | — | — | — | — | manual (stage)¹ |
| Claude Desktop (connector) | — | — | — | — | — | — | — | — | — | — | — | — |
| Claude Desktop (`mcp-remote`) | — | — | — | — | — | — | — | — | — | — | — | — |
| Cursor (desktop) | — | — | — | — | — | — | — | — | — | — | — | — |
| MCP Inspector | — | — | — | — | — | — | — | — | — | — | — | manual (stage)² |
| Python `mcp` SDK | 2.3.0 | 2026-07-28 | yes | yes | yes | yes | yes | yes | yes | 0.6.0 | 2026-10-14 | CI |
| MCP 2026-07-28 client | 2.3.0 | 2026-07-28 | yes | yes | yes | yes | yes | yes | yes | 0.6.0 | 2026-10-14 | CI |
| Handshake-protocol client | 2.3.0 | handshake | yes | yes | yes | yes | yes | yes | n/a³ | 0.6.0 | 2026-10-14 | CI |

When one product supports both protocol eras, add separate rows and note the
era in **MCP protocol**.

¹ `claude mcp add` / `claude mcp list` work without Anthropic credentials (Keystone
shows as “Needs authentication”); CI does not run this yet — Node.js in CI is
blocked on product-owner decision OV-F6.

² MCP Inspector `--cli` accepts a Bearer service-account key for `tools/list` and
`tools/call`; OAuth browser sign-in is not supported in CLI mode.

³ Handshake-era run: demo `hello-upstream` (SDK 1.28) does not expose elicitation;
`scripts/client_e2e.py` skips that step (`skip elicitation`).

### How this table is maintained

Before each release, an operator runs the [release checklist](clients-checklist.md)
on stage (or the compose demo with public HTTPS for the Claude Desktop
connector). Each verified client gets a row with the Keystone-MCP version and
date. Rows not re-checked in a release keep the previous **Checked with
Keystone-MCP** value so stale entries stay visible.

## Known client behaviour

**Redirect URIs.** Each OAuth client returns to a different host or custom
scheme. When the operator sets `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`, they
must allow the host each client uses — see
[Allowed redirect hosts](#keystone_mcp_oauth_allowed_redirect_hosts) below.

**`Origin: null`.** Some desktop clients built on Electron send
`Origin: null` on HTTP requests. Which routes and user agents do this is
recorded after the stage measurement described in the release checklist
(step 4); until that run, treat it as unknown.

**Dynamic registration.** Keystone expires unused registered OAuth clients
after 24 hours of non-use. Clients that cache registration may register again on
the next connect after idle — this is expected, not a sign-in failure.

**`list_changed`.** Keystone sends `notifications/tools/list_changed` when
the catalog changes, but only clients that keep a live notification stream
(or MCP 2026-07-28 `subscriptions/listen`) update without reconnecting. Others
need disable/enable or a new session — see [If sign-in does not work](#if-sign-in-does-not-work).

**Elicitation.** Form-mode questions from upstream tools appear only when the
client declared elicitation support; Keystone prefixes proxied messages with
`[namespace]`. URL-mode elicitation is declined. Not every client shows
service questions.

**Cancellation.** Whether closing a chat cancels an in-flight tool call depends
on the client; verify on the checklist with `hello_slow_count`.

## Before you start

You need:

- The server address.
- Your email, already added to the users directory by an administrator. A
  client that reaches `/login` with an email the directory does not know
  still gets refused — sign-in and "being a known user" are two separate
  checks.
- Access through one of the sign-in methods the operator configured (Google,
  any OpenID Connect provider, or the API-key form). See
  [login-providers.md](login-providers.md).

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
sign-in page: enter your email, complete the sign-in method your operator
enabled, then **Authorize**.

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
6. Click **Add**, then sign in on the page that opens using the sign-in
   methods your operator configured.

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
cannot register itself, ask the operator to run
`keystone-mcp oauth register-client` — see
[Registering a client manually](environment.md#registering-a-client-manually).

### `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`

An operator who restricts return addresses with this variable needs the
exact host each client redirects back to:

| Client | Host to allow |
|---|---|
| Claude Code | `localhost` (it listens on a different local port each time; the restriction matches on host only) |
| Cursor, desktop app | its custom-scheme callback as a `scheme://host` entry, e.g. `cursor://anysphere.cursor-retrieval` (confirm the host in the server log, see below); a bare `localhost` does not cover a `cursor://` redirect |
| Cursor, web and Background Agents | `cursor.com` |
| Claude Desktop, `mcp-remote` bridge | `localhost` |
| Claude Desktop, custom connector | `claude.ai` |

For a client not listed here, turn the restriction on with any entry (for
example `localhost`), start the sign-in once, then search the server log
for `redirect_uri host not allowed` — it names the host the client asked
for. The log shows the host only: if the client's redirect uses a custom
scheme (not `http`/`https`), the entry must be `scheme://host`, not the
bare host.

## Machines (service accounts)

Scripts, CI jobs, and other non-interactive callers use a **service account**
(`svc:<name>`) and an API key issued on the server. Ask an administrator to
create the account and run `keystone-mcp keys issue` (or use a non-production
deployment where the `api_keys_issue` tool is available). Store the key like
any other secret; you cannot retrieve it again from Keystone.

### Python (`fastmcp`)

```python
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

transport = StreamableHttpTransport(
    "https://mcp.example.com/mcp/",
    headers={"Authorization": "Bearer ksk_<key_id>_<secret>"},
)
async with Client(transport) as client:
    await client.ping()
```

### Claude Code (HTTP with a fixed header)

```bash
claude mcp add --transport http keystone-bot https://mcp.example.com/ \
  --header "Authorization: Bearer ksk_<key_id>_<secret>"
```

Use the exact URL and path your operator gave you. The key must belong to the
service account that holds the roles your automation needs.

## If sign-in does not work

| Symptom | Fix |
|---|---|
| The browser did not open | Copy the URL the client printed (Claude Code and `mcp-remote` both print "visit this URL to authorize") and open it yourself. |
| Refused after sign-in, or "unknown user" | Your email is not yet in the users directory. Ask an administrator to add it — this applies to every sign-in method alike. |
| Google sign-in fails with `redirect_uri_mismatch` | This is on the operator's side: the Google OAuth client's redirect URI does not match. See [google-oauth.md](google-oauth.md). |
| The client shows an old or missing tool list | Keystone-MCP sends `notifications/tools/list_changed` after a catalog change, but only a client that is connected and listening for it (the standalone SSE stream, or a `subscriptions/listen` stream on MCP 2026-07-28) receives it live; otherwise reconnect (disable, then enable, the server). See [facade.md](facade.md). |
| `http://` to a public address is refused | Use `https://`. A `production`-profile server refuses a plain-`http` address once it is reachable publicly. |
| `421 Misdirected Request` | The address you connected to is not the server's own name. Use exactly the host in `KEYSTONE_MCP_BASE_URL` (for the local demo, `localhost`, `127.0.0.1` or `[::1]` on the same port); an operator can allow another name with `KEYSTONE_MCP_ALLOWED_HOSTS`. |
