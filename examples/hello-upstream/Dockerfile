# hello-upstream: a tiny demo MCP server for the Keystone-MCP compose demo.
# Build context is this directory only (examples/hello-upstream/).

FROM python:3.12-slim

# Pinned to the "mcp" version Keystone-MCP itself locks (see ../../uv.lock),
# so the demo exercises the same SDK release.
RUN pip install --no-cache-dir mcp==1.28.1

RUN groupadd --system --gid 10001 hello \
    && useradd --system --uid 10001 --gid hello \
       --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin hello

WORKDIR /app
COPY server.py ./server.py

USER hello:hello
EXPOSE 8081

HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz')"]

CMD ["python", "server.py"]
