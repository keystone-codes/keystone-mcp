# RBAC catalog registry CLI

Offline checks for RBAC policy files against a **live published-tool list** and an
optional **catalog snapshot**. The same validation path runs at server startup
(`assert_live_catalog_validation`); this CLI lets CI and operators run it without
starting the full process.

Security: the CLI only reads local files and optional HTTP URLs you pass explicitly.
`--live-url` is enforced to `http://<loopback>/internal/live-published-names` only
(for example `http://127.0.0.1:8080/internal/live-published-names` in CI). Other
schemes, hosts, or paths are rejected before any fetch.

## Live name list format

One client-visible published name per line, with multiplicity preserved. This matches
`python -m keystone_mcp.rbac.catalog` and the server's
`/internal/live-published-names` endpoint.

## Commands

### `keystone-mcp catalog validate`

```bash
keystone-mcp catalog validate \
  --policy config/rbac-policy.yaml \
  --snapshot examples/catalog-snapshot.example.yaml \
  --live-file /tmp/live-names.txt
```

| Flag | Purpose |
|------|---------|
| `--policy PATH` | Required RBAC policy file |
| `--snapshot PATH` | Optional snapshot (`active` / `reserved` / `wip`) |
| `--live-file PATH` | Live names from a file |
| `--live-url URL` | Live names fetched over HTTP (localhost CI) |
| `--strict-unreachable` | Exit non-zero when any tool is unreachable by every role (normally logged as WARNING only) |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Policy and catalog are consistent |
| `1` | Validation error (structure, unmatched allows, duplicate live names, or `--strict-unreachable`) |
| `3` | `--live-url` fetch failed |

### `keystone-mcp catalog diff`

Same inputs as `validate`, but prints a human-readable summary to stdout:

- **Only in live** — live tool names no role can reach
- **Unmatched allow patterns** — allow rows that match nothing in live ∪ snapshot

Does not refuse on unmatched patterns; use `validate` for a hard gate.

### `keystone-mcp catalog export`

Build a snapshot snippet from a live name file:

```bash
keystone-mcp catalog export --live-file /tmp/live-names.txt --tier active
```

Emits YAML with a single section (`active` by default). Paste into your catalog
snapshot file or pipe to a new file.

## Related docs

- [RBAC policy file format](rbac-policy-format.md) — policy and snapshot semantics
- `python -m keystone_mcp.rbac.catalog` — dump live names from a running server
