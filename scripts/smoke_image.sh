#!/usr/bin/env bash
# Start a built keystone-mcp image against Redis and check that it actually
# serves traffic: /healthz, /readyz (200), container HEALTHCHECK status
# "healthy", and the process runs as the unprivileged uid 10001.
#
# Usage: scripts/smoke_image.sh IMAGE
#
# On any failure, the app container's logs are printed before exiting.
# Containers and the dedicated network are always removed on exit, success
# or failure (trap on EXIT).
set -euo pipefail

IMAGE="${1:?Usage: scripts/smoke_image.sh IMAGE}"

PORT=18080
HOST="127.0.0.1"
WAIT_SECONDS=60

NETWORK="ks-smoke-$$"
REDIS_NAME="ks-smoke-redis-$$"
APP_NAME="ks-smoke-app-$$"

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && docker inspect "${APP_NAME}" >/dev/null 2>&1; then
    log "--- docker logs ${APP_NAME} (smoke failed, status ${status}) ---"
    docker logs "${APP_NAME}" 2>&1 || true
    log "--- end docker logs ---"
  fi
  docker rm -f "${APP_NAME}" "${REDIS_NAME}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT

# Fail fast with a clear message instead of waiting out the 60s health loop
# below if the port the smoke app will be published on is already taken.
if (exec 3<>"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
  exec 3<&- 2>/dev/null || true
  exec 3>&- 2>/dev/null || true
  die "port ${HOST}:${PORT} is already in use; free it before running this script"
fi

log "Creating network ${NETWORK} and starting Redis (${REDIS_NAME})..."
docker network create "${NETWORK}" >/dev/null
docker run -d --name "${REDIS_NAME}" --network "${NETWORK}" redis:7-alpine >/dev/null

log "Starting ${IMAGE} as ${APP_NAME} on ${HOST}:${PORT}..."
docker run -d \
  --name "${APP_NAME}" \
  --network "${NETWORK}" \
  -p "${HOST}:${PORT}:8080" \
  -e "KEYSTONE_MCP_REDIS_URL=redis://${REDIS_NAME}:6379/0" \
  -e "KEYSTONE_MCP_BASE_URL=http://localhost:${PORT}" \
  -e "KEYSTONE_MCP_DEPLOYMENT_PROFILE=local" \
  "${IMAGE}" >/dev/null

log "Waiting up to ${WAIT_SECONDS}s for /healthz..."
deadline=$((SECONDS + WAIT_SECONDS))
until curl -fsS "http://${HOST}:${PORT}/healthz" >/dev/null 2>&1; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    die "/healthz did not respond within ${WAIT_SECONDS}s"
  fi
  sleep 1
done
log "/healthz OK."

log "Checking /readyz returns 200..."
curl -fsS "http://${HOST}:${PORT}/readyz" >/dev/null || die "/readyz did not return 200"
log "/readyz OK."

log "Waiting up to ${WAIT_SECONDS}s for container health status 'healthy'..."
deadline=$((SECONDS + WAIT_SECONDS))
status="unknown"
while true; do
  status="$(docker inspect --format '{{.State.Health.Status}}' "${APP_NAME}")"
  if [ "${status}" = "healthy" ]; then
    break
  fi
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    die "container health status is '${status}', expected 'healthy' after ${WAIT_SECONDS}s"
  fi
  sleep 1
done
log "Container HEALTHCHECK is healthy."

log "Checking the process runs as uid 10001..."
uid="$(docker exec "${APP_NAME}" id -u)"
if [ "${uid}" != "10001" ]; then
  die "container runs as uid ${uid}, expected 10001"
fi
log "Runs as uid 10001."

log "Smoke OK: ${IMAGE}"
