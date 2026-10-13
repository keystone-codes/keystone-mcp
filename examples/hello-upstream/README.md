# hello-upstream

A tiny demo MCP server used by [`docker-compose.demo.yml`](../../docker-compose.demo.yml)
to stand in for a real upstream service behind Keystone-MCP. Built on the
low-level `mcp` SDK, not FastMCP, so it behaves like a server written in
another language (TypeScript, Go, or this SDK) -- exactly the servers
Keystone-MCP's proxy has to work with in the wild.

## Tools

- **`greet(name)`** -- answers with plain text, not JSON. Shows that
  Keystone-MCP forwards whatever shape a tool naturally returns. If the
  request carries a verified identity (see below), the greeting names the
  caller and their roles; otherwise, if it carries `X-Author-Email`
  (Keystone-MCP adds it after verifying the caller's identity), the greeting
  names that email instead.
- **`search(query, limit=5, filter)`** -- its `inputSchema` declares the
  optional `limit` before the required `filter`. Valid JSON Schema, but many
  non-Python MCP servers produce schemas like this, and it is exactly the
  shape that used to break Keystone-MCP's discovery.
- **`whoami()`** -- returns the verified identity fields as JSON text:
  `sub`, `sub_type`, `roles`, `auth_method`, `interactive`, `client_id`,
  `mcp_target`. Without `HELLO_IDENTITY_SECRET` configured (below), returns
  `{"verified": false, "x-author-email": ...}` instead.

## Running it standalone

```bash
docker build -t hello-upstream examples/hello-upstream
docker run --rm -p 127.0.0.1:8081:8081 hello-upstream
```

MCP is served over Streamable HTTP on `http://127.0.0.1:8081/mcp`; a plain
health check answers at `GET /healthz`.

This demo upstream intentionally uses MCP Python SDK 1.x, so the demo shows
Keystone proxying a server that speaks the older handshake protocol.

## Verifying `X-Keystone-Identity`

Set `HELLO_IDENTITY_SECRET` to make this server verify the signed
`X-Keystone-Identity` assertion on every tool call instead of trusting the
unsigned, deprecated `X-Author-Email` outright -- the same check any upstream
service should run (see
[`docs/connecting-services.md`](../../docs/connecting-services.md), section
"Who is calling: X-Keystone-Identity"). `keystone_identity.py` next to this
server is a copy of
[`examples/keystone-identity/python/keystone_identity.py`](../keystone-identity/python/keystone_identity.py);
the same logic a service in any other language would run against
[`examples/keystone-identity/typescript/`](../keystone-identity/typescript/).

- `HELLO_IDENTITY_SECRET` -- the shared secret (must match the upstream
  registry entry's `auth.identity_secret_env` value on the Keystone-MCP
  side). Unset by default: the server then falls back to trusting
  `X-Author-Email` outright, exactly like 0.4.0.
- `HELLO_IDENTITY_AUDIENCE` -- this upstream's own registry entry `name`,
  i.e. the assertion's `aud`. Defaults to `hello`, matching
  [`examples/demo/upstreams.yaml`](../demo/upstreams.yaml).

A request with no valid assertion is rejected once `HELLO_IDENTITY_SECRET` is
set, even if it carries a forged `X-Author-Email`. With the compose demo
running (`docker compose -f docker-compose.demo.yml up -d --build --wait`),
confirm this directly against the container, bypassing Keystone-MCP:

```bash
docker compose -f docker-compose.demo.yml exec hello-upstream python -c "
import json, urllib.request
body = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
    'params': {'name': 'whoami', 'arguments': {}},
}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:8081/mcp',
    data=body,
    method='POST',
    headers={
        'Accept': 'application/json, text/event-stream',
        'Content-Type': 'application/json',
        'X-Author-Email': 'boss@example.com',
    },
)
with urllib.request.urlopen(req) as resp:
    print(resp.status, resp.read().decode())
"
```

The response's `result.isError` is `true` and its text contains
`identity rejected` -- the forged `X-Author-Email` alone convinces no one
once the upstream actually checks the signed assertion.

Without `HELLO_IDENTITY_SECRET` set, the server reads `X-Author-Email` and
trusts it outright -- no signature, no secondary check. That is only safe
because, in the demo, this service never receives traffic except from
Keystone-MCP over a private Docker network. See
[`docs/connecting-services.md`](../../docs/connecting-services.md) for the
full contract an upstream service should meet, including how to require a
bearer token from Keystone-MCP as well.
