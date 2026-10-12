# hello-upstream

A tiny demo MCP server used by [`docker-compose.demo.yml`](../../docker-compose.demo.yml)
to stand in for a real upstream service behind Keystone-MCP. Built on the
low-level `mcp` SDK, not FastMCP, so it behaves like a server written in
another language (TypeScript, Go, or this SDK) -- exactly the servers
Keystone-MCP's proxy has to work with in the wild.

## Tools

- **`greet(name)`** -- answers with plain text, not JSON. Shows that
  Keystone-MCP forwards whatever shape a tool naturally returns. If the
  request carries `X-Author-Email` (Keystone-MCP adds it after verifying the
  caller's identity), the greeting names that email too.
- **`search(query, limit=5, filter)`** -- its `inputSchema` declares the
  optional `limit` before the required `filter`. Valid JSON Schema, but many
  non-Python MCP servers produce schemas like this, and it is exactly the
  shape that used to break Keystone-MCP's discovery.

## Running it standalone

```bash
docker build -t hello-upstream examples/hello-upstream
docker run --rm -p 127.0.0.1:8081:8081 hello-upstream
```

MCP is served over Streamable HTTP on `http://127.0.0.1:8081/mcp`; a plain
health check answers at `GET /healthz`.

This demo upstream intentionally uses MCP Python SDK 1.x, so the demo shows
Keystone proxying a server that speaks the older handshake protocol.

## Trusting `X-Author-Email`

The server reads `X-Author-Email` and trusts it outright -- no signature, no
secondary check. That is only safe because, in the demo, this service never
receives traffic except from Keystone-MCP over a private Docker network. See
[`docs/connecting-services.md`](../../docs/connecting-services.md) for the
full contract an upstream service should meet, including how to require a
bearer token from Keystone-MCP as well.
