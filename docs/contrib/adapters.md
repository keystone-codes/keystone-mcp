# Reference adapters

Two `Adapter` implementations in `keystone_mcp.contrib.adapters`, shipped as
a starting point for a fork — see [contrib/README.md](README.md) for what
"contrib" means and why they are not covered by the compatibility promise
([compatibility.md](../compatibility.md)).

Neither adapter is registered by Keystone-MCP itself. To use one, register a
route with it as the target:

```python
from keystone_mcp.contrib.adapters import WebhookAdapter

registry.add_route(
    "submit_task",
    WebhookAdapter(),
    mode="live",
    params=[Param("project_id", str), Param("changes", dict)],
)
```

## `WebhookAdapter`

Async submit to a webhook API, with a deterministic peek and a long-poll
against a task-result endpoint:

1. **peek** — `GET {base_url}/tasks/{task_id}/result`. A `done`, `error` or
   `file_ready` state here short-circuits the call: the webhook is **not**
   sent and the handler is not re-run.
2. **submit** — `POST {base_url}/api/v1/webhooks/{client}/{project}` with the
   call's arguments (or the route's `transform` output, if one is set) as the
   JSON body.
3. **poll** — `GET {base_url}/tasks/{task_id}/result` every `poll_interval`
   seconds (constructor argument, default 1.0) until the state is `done`,
   `error`, `awaiting_user` or `file_ready`, or `long_poll_seconds` elapses.
   On timeout the adapter returns `{"state": "pending", "task_id": ..., "tool": ...}`.

Every request carries the verified identity as `X-Author-Email` (the same
header the rest of Keystone-MCP uses) and, when set, `api_token` as a raw
`Authorization` header — the adapter does not know or care what scheme the
target expects.

### Settings

`WebhookAdapter(settings=None, ...)` reads `WebhookSettings.from_env()` when
`settings` is omitted, **at construction time** — not on each call. Pass a
`WebhookSettings` explicitly to configure it another way (tests do this).

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL` | — | Base URL the adapter submits to and polls. No default: empty is a configuration error, the same as an empty client/project. |
| `KEYSTONE_MCP_CONTRIB_WEBHOOK_CLIENT` | — | Webhook route client segment. |
| `KEYSTONE_MCP_CONTRIB_WEBHOOK_PROJECT` | — | Webhook route project segment. |
| `KEYSTONE_MCP_CONTRIB_WEBHOOK_API_TOKEN` | `""` | Optional token sent as a raw `Authorization` header. |
| `KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS` | `40` | Long-poll budget, seconds, before the adapter returns a `pending` envelope. A non-integer value raises `ValueError` naming the variable. |

If `base_url`, `client` or `project` is empty when a call is made, the
adapter returns `{"state": "error", "code": "webhook_target_unconfigured", ...}`
without making any network call.

## `ExternalHttpAdapter`

Routes a tool call to an arbitrary external HTTP API. The route's
`transform` prepares the payload and may switch the HTTP method (`GET` or
`POST`) and path; without a `transform` the raw arguments are sent as the
JSON body (`POST`) or query parameters (`GET`).

The adapter never lets the caller set `X-Author-Email` or `Authorization` on
the outbound request — both are decided by the adapter, case-insensitively,
so a `transform`-supplied `x-author-email` or any other spelling of either
header is dropped and replaced with the verified identity. This is identity
propagation, not an auth bypass: the target is expected to validate the
header against its own authority.

`ExternalHttpAdapter` has no environment-backed settings; `base_url`,
`method` and `path` are constructor arguments.
