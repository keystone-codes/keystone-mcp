# Release checklist — tested MCP clients

Steps 1–7 for the Python `mcp` SDK run in CI (`scripts/client_e2e.py`); repeat
them by hand for desktop clients.

Run this checklist on a fresh deployment (stage or the local compose demo with
public HTTPS when you need Claude Desktop's cloud connector) before each
release. Record the outcome as rows in the [Tested clients](clients.md#tested-clients)
table with the Keystone-MCP version and date.

Use the demo upstream's `hello_greet` (or another tool your stand exposes) for
tool calls unless noted. For progress, cancellation, and elicitation, use the
demo upstream's `hello_slow_count` and `hello_ask_name` when those tools are
published to your role.

## Per client

1. **Registration and sign-in.** Remove the client's saved sign-in; connect
   again. The client registers (`POST /register`), opens the sign-in page, and
   after sign-in the consent screen shows the application name and return
   address. The Keystone log must not contain `redirect_uri host not allowed`.
   Note the client version and MCP protocol (Keystone logs the session protocol
   version).
2. **Tools.** `tools/list` shows tools for your role; calling `hello_greet`
   (or your stand's equivalent) succeeds.
3. **Token refresh.** On the stand, set `KEYSTONE_MCP_TOKEN_TTL=300`. Six
   minutes later, call a tool without signing in again. The log must show a
   refresh-token exchange. Record how many exchanges hit the refresh grace
   window (record after the stage grace-window measurement — leave blank until
   that run).
4. **`Origin: null`.** After steps 1–3, record routes and `User-Agent` values
   from the stage `Origin: null` measurement
   (`keystone_mcp_http_origin_null_total{route=…}` when that metric exists).
   Leave blank until measured on stage.
5. **`list_changed`.** While the client stays connected, change policy (another
   administrator uses `policy_allow_add`, or edit the policy file and send
   `SIGHUP`). Did the client refresh its tool list without reconnecting?
   (`yes` / `no`).
6. **Progress and cancel.** Call `hello_slow_count` with a large `n`. Does the
   client show progress? Close the tool call or chat: does the upstream log
   show cancellation?
7. **Elicitation.** Call `hello_ask_name`. Does the client show the form
   question (with a `[hello]` prefix when proxied through Keystone)? Does the
   answer reach the upstream?
8. **Sign out and sign in again.** Use the "sign in as someone else" steps
   from [clients.md](clients.md) for that client.
9. **Record the table row** in [clients.md](clients.md#tested-clients).
10. **Clean machine (once per release, separate from clients).** Someone
    without prior Keystone experience on a machine with no configured
    environment follows [README.md](../README.md) and
    [paths/local-compose.md](paths/local-compose.md), starts the demo, signs
    in with a client, and confirms that removing a role hides tools. Note time
    spent and where they got stuck in the release PR description.

## Clients to cover

- Claude Code
- Claude Desktop — custom connector (public HTTPS only)
- Claude Desktop — `mcp-remote` bridge (local HTTP)
- Cursor (desktop app)
- MCP Inspector
- Python `mcp` SDK client (CI row when automated)
- Any client you rely on that negotiates MCP 2026-07-28 vs the handshake
  protocol — use separate table rows when one product supports both.

Rows you could not verify stay `—` in the table with a footnote explaining why.
