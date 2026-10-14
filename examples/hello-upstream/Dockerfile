# hello-upstream: a tiny demo MCP server for the Keystone-MCP compose demo.
# Build context is this directory only (examples/hello-upstream/).

FROM python:3.12-slim

# Pinned to MCP Python SDK 1.x on purpose: Keystone-MCP itself moved to SDK 2
# (see ../../uv.lock), so this demo upstream deliberately stays behind to
# exercise the older handshake protocol through Keystone-MCP's proxy.
# pyjwt verifies X-Keystone-Identity (see keystone_identity.py); pinned to
# the same version Keystone-MCP itself uses (../../uv.lock).
RUN pip install --no-cache-dir \
    mcp==1.28.1 \
    pyjwt==2.15.1 \
    opentelemetry-sdk==1.45.1 \
    opentelemetry-exporter-otlp-proto-http==1.45.1

RUN groupadd --system --gid 10001 hello \
    && useradd --system --uid 10001 --gid hello \
       --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin hello

WORKDIR /app
COPY server.py keystone_identity.py ./

USER hello:hello
EXPOSE 8081

HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz')"]

CMD ["python", "server.py"]
