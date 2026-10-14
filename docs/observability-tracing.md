# OpenTelemetry tracing

Tracing is **optional**. With `KEYSTONE_MCP_OTEL_ENABLED=false` (default) behavior and performance are unchanged.

## Enable

1. Install the `otel` extra: `pip install 'keystone-mcp-gateway[otel]'` (included in the published image).
2. Set `KEYSTONE_MCP_OTEL_ENABLED=true`.
3. Configure export with standard OpenTelemetry variables, for example:
   - `OTEL_EXPORTER_OTLP_ENDPOINT` (HTTP/protobuf, port 4318 for Jaeger)
   - `OTEL_SERVICE_NAME` (defaults to `keystone-mcp` in code when unset)
   - `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`

Keystone does not define custom export or sampler variables beyond `KEYSTONE_MCP_OTEL_ENABLED`.

## Spans

| Span | Attributes (non-exhaustive) |
|------|-----------------------------|
| HTTP `{method} {route}` | `http.request.method`, `http.route`, `http.response.status_code`, `keystone.request_id` |
| `keystone.token.verify` | `keystone.token.found`, `keystone.auth_method` |
| `keystone.rbac.decide` | `keystone.rbac.mode`, `keystone.rbac.decision`, `keystone.rbac.reason`, `keystone.mcp.operation`, `keystone.tool` |
| `keystone.directory.resolve` | `keystone.directory.backend`, `keystone.directory.cache_hit`, `keystone.subject` (hash) |
| `keystone.redis.*` | `db.system.name`, `db.operation.name` |
| `keystone.upstream.call` | `keystone.upstream.namespace`, `keystone.upstream.transport`, `keystone.mcp.method`, `keystone.upstream.tool` |

Probes `/healthz` and `/readyz` do not create HTTP spans. Span names and attributes are not frozen in `docs/compatibility.md`.

Email, tokens, Redis keys, client IP, and raw request paths are not recorded.

## Client and upstream context

- Clients may send W3C `traceparent` / `tracestate` on HTTP requests; Keystone accepts the context (sampler decides whether to record).
- On upstream HTTP calls, Keystone injects `traceparent` before registry static headers and identity headers. MCP `_meta.traceparent` is handled by the MCP SDK (SEP-414).
- If tracing is disabled at Keystone but the client sent `traceparent` in MCP `_meta`, the SDK may still forward that context upstream (identifiers only).

## Demo with Jaeger

```bash
docker compose -f docker-compose.demo.yml -f examples/tracing/docker-compose.tracing.yml up -d --build --wait
```

Open Jaeger at http://localhost:16686 and search for a `hello_greet` call.

## Sampling

Default SDK sampling applies (`parentbased_always_on`). To limit cost when clients always sample, set e.g. `OTEL_TRACES_SAMPLER=traceidratio` and `OTEL_TRACES_SAMPLER_ARG=0.1`.
