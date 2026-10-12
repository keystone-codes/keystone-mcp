# 0006 — File transfer is an upstream service; reference adapters live in contrib

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Keystone-MCP is a gateway: identity, policy, and proxying. A first-party file
upload/download API would freeze foreign contracts in the core compatibility
promise and duplicate what a dedicated MCP upstream can provide.

## Decision

We removed the core file tools (`create_upload_url`, `get_download_link`), file
API adapters, and `KEYSTONE_MCP_FILE_API_URL` from the product. File transfer
belongs behind the registry like any other upstream MCP service
([connecting-services.md](../connecting-services.md)).

Reference HTTP adapters (`WebhookAdapter`, `ExternalHttpAdapter`) live in
`keystone_mcp.contrib`. Keystone-MCP does not register them; forks import and
mount them. Their settings use the `KEYSTONE_MCP_CONTRIB_*` prefix and are
documented under [docs/contrib/](../contrib/), not in the core environment
tables.

## Consequences

The frozen core stays smaller and free of storage-vendor choices. Forks that need
webhooks or generic HTTP bridging copy contrib code explicitly, without implying
long-term API stability for those classes.

Operators who relied on the old file tools must drop the env var and policy
entries, then expose files through a separate upstream.

## Alternatives considered

**Keep file tools in core** — Expands the compatibility surface; rejected.

**Move file tools to contrib but still ship them** — Would still imply support
for a file contract; rejected after owner decision to delete the API.

**Built-in S3 storage** — Storage policy and credentials belong in a dedicated
service; not planned in core.

## Links

- [facade.md](../facade.md), [contrib/README.md](../contrib/README.md)
- `src/keystone_mcp/contrib/`
