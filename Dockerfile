# Multi-stage build: uv lockfile install in builder, slim runtime without uv.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY config ./config
COPY src ./src

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

FROM python:3.12-slim-bookworm AS runtime

ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --system --gid "${APP_GID}" keystone \
    && useradd --system --uid "${APP_UID}" --gid keystone \
       --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin keystone \
    && mkdir -p /data \
    && chown keystone:keystone /data

WORKDIR /app

COPY --from=builder /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    KEYSTONE_MCP_HOST=0.0.0.0 \
    KEYSTONE_MCP_PORT=8080 \
    KEYSTONE_MCP_USERS_DB_URL=sqlite:////data/keystone-users.db

VOLUME ["/data"]
EXPOSE 8080
USER keystone:keystone

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-m", "keystone_mcp.healthcheck", "/readyz"]

CMD ["python", "-m", "keystone_mcp.server"]
