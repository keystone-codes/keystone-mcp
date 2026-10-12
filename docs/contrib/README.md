# contrib

`keystone_mcp.contrib` is reference code for forks. It ships in the same
package as everything else, but it is **not covered by the compatibility
promise** (`docs/compatibility.md`): a class, a function signature or a
variable name under `contrib/` can change in a minor release, with a note in
[CHANGELOG.md](../../CHANGELOG.md).

Keystone-MCP itself registers nothing from `contrib/` — there is no
environment variable that turns it on. A fork that wants one of these
adapters imports the class and registers a route with it as the target, the
same way it would register any other `Adapter` (see
[adding-routes.md](../adding-routes.md)).

Settings under `contrib/` use the `KEYSTONE_MCP_CONTRIB_` prefix, are read
only by the class that owns them (at construction time, not from the shared
`Settings` object), and are documented here, not in
[environment.md](../environment.md) or `.env.example`.

## Pages

- [adapters.md](adapters.md) — `WebhookAdapter` and `ExternalHttpAdapter`:
  what each does, their settings, and how to register one.
