#!/usr/bin/env bash
# Start the `keystone-mcp` command installed from a built wheel and check
# that it actually serves traffic: /healthz, then /readyz (200).
#
# Usage: scripts/smoke_wheel.sh KEYSTONE_BIN
#
#   KEYSTONE_BIN  path to the installed `keystone-mcp` entry point, e.g.
#                 /tmp/venv/bin/keystone-mcp (see release.yml's wheel-smoke
#                 job and ci.yml's package job, which `pip install` the
#                 wheel built by `uv build` into a clean virtualenv first).
#
# Needs a Redis reachable at redis://localhost:6379/0 (the release and CI
# workflows run one as a service container on the default port).
#
# On any failure, the server's captured stdout/stderr is printed before
# exiting. The server process is always stopped on exit, success or failure
# (trap on EXIT).
set -euo pipefail

KEYSTONE_BIN="${1:?Usage: scripts/smoke_wheel.sh KEYSTONE_BIN}"

PORT=18081
HOST="127.0.0.1"
WAIT_SECONDS=60

LOG_FILE="$(mktemp -d)/keystone-mcp-smoke.log"
USERS_DB_DIR="$(mktemp -d)"

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

SERVER_PID=""

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && [ -f "${LOG_FILE}" ]; then
    log "--- ${KEYSTONE_BIN} serve log (smoke failed, status ${status}) ---"
    cat "${LOG_FILE}" || true
    log "--- end log ---"
  fi
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  return "$status"
}
trap cleanup EXIT

# Fail fast with a clear message instead of waiting out the 60s health loop
# below if the port this smoke run will listen on is already taken.
if (exec 3<>"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
  exec 3<&- 2>/dev/null || true
  exec 3>&- 2>/dev/null || true
  die "port ${HOST}:${PORT} is already in use; free it before running this script"
fi

log "Starting ${KEYSTONE_BIN} serve on ${HOST}:${PORT}..."
KEYSTONE_MCP_DEPLOYMENT_PROFILE=local \
  KEYSTONE_MCP_BASE_URL="http://localhost:${PORT}" \
  KEYSTONE_MCP_PORT="${PORT}" \
  KEYSTONE_MCP_REDIS_URL="redis://localhost:6379/0" \
  KEYSTONE_MCP_USERS_DB_URL="sqlite:///${USERS_DB_DIR}/users.db" \
  KEYSTONE_MCP_SUPERADMIN_EMAIL="admin@example.com" \
  KEYSTONE_MCP_DEV_TOKENS="smoke-token" \
  "${KEYSTONE_BIN}" serve >"${LOG_FILE}" 2>&1 &
SERVER_PID=$!

log "Waiting up to ${WAIT_SECONDS}s for /healthz..."
deadline=$((SECONDS + WAIT_SECONDS))
until curl -fsS "http://${HOST}:${PORT}/healthz" >/dev/null 2>&1; do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    die "${KEYSTONE_BIN} serve exited before becoming healthy"
  fi
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    die "/healthz did not respond within ${WAIT_SECONDS}s"
  fi
  sleep 1
done
log "/healthz OK."

log "Checking /readyz returns 200..."
curl -fsS "http://${HOST}:${PORT}/readyz" >/dev/null || die "/readyz did not return 200"
log "/readyz OK."

# X09 appends a "$KEYSTONE_BIN plugins list" check here once that
# subcommand exists.

log "Smoke OK: ${KEYSTONE_BIN} serve"
