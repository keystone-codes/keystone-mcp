#!/usr/bin/env bash
# Idempotent deploy: git sync, uv install, optional systemd restart, /healthz then /readyz.
# Run from the repository root, e.g. ./scripts/deploy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${DEPLOY_REF:-}" ]]; then
  if [[ -n "${DEPLOY_BRANCH:-}" ]]; then
    printf 'WARNING: DEPLOY_BRANCH is deprecated, use DEPLOY_REF\n' >&2
  fi
  DEPLOY_REF="${DEPLOY_BRANCH:-master}"
fi
DEPLOY_SERVICE="${DEPLOY_SERVICE:-keystone-mcp.service}"
DEPLOY_HEALTH_URL="${DEPLOY_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
DEPLOY_READY_URL="${DEPLOY_READY_URL:-http://127.0.0.1:8080/readyz}"
DEPLOY_READY_TIMEOUT="${DEPLOY_READY_TIMEOUT:-60}"
SKIP_GIT="${SKIP_GIT:-0}"
SKIP_RESTART="${SKIP_RESTART:-0}"
SKIP_SMOKE="${SKIP_SMOKE:-0}"

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

if [[ "$SKIP_GIT" != "1" ]]; then
  if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    die "Not a git clone at ${ROOT}; /opt layout without git: see docs/deploy.md (pip upgrade) or clone with git"
  fi
  log "Syncing git (ref ${DEPLOY_REF})..."
  git fetch --tags --force origin
  if git rev-parse -q --verify "refs/tags/${DEPLOY_REF}" >/dev/null 2>&1; then
    git checkout --detach "$DEPLOY_REF"
  else
    git checkout "$DEPLOY_REF"
    git pull --ff-only origin "$DEPLOY_REF"
  fi
else
  log "SKIP_GIT=1 — leaving working tree unchanged."
fi

deploy_commit="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "Deploying ${DEPLOY_REF} (${deploy_commit})"

if ! command -v uv >/dev/null 2>&1; then
  die "uv is required (https://docs.astral.sh/uv/)."
fi

log "Installing Python dependencies (uv sync --locked --no-dev --no-editable)..."
uv sync --locked --no-dev --no-editable

restart_service() {
  if [[ "$SKIP_RESTART" == "1" ]]; then
    log "SKIP_RESTART=1 — not restarting ${DEPLOY_SERVICE}."
    return 0
  fi

  log "Restarting ${DEPLOY_SERVICE} (sudo required for systemctl)..."
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    systemctl restart "$DEPLOY_SERVICE"
    systemctl is-active --quiet "$DEPLOY_SERVICE"
  elif command -v sudo >/dev/null 2>&1; then
    if ! sudo -n true 2>/dev/null; then
      die "Passwordless sudo is not available. Run: sudo systemctl restart ${DEPLOY_SERVICE}"
    fi
    sudo systemctl restart "$DEPLOY_SERVICE"
    sudo systemctl is-active --quiet "$DEPLOY_SERVICE"
  else
    die "sudo not found. Run: systemctl restart ${DEPLOY_SERVICE}"
  fi
  log "${DEPLOY_SERVICE} is active."
}

smoke_ready() {
  if [[ "$SKIP_SMOKE" == "1" || "$SKIP_RESTART" == "1" ]]; then
    [[ "$SKIP_SMOKE" == "1" ]] && log "SKIP_SMOKE=1 — skipping readiness checks."
    return 0
  fi

  log "Smoke check: GET ${DEPLOY_HEALTH_URL}"
  if ! curl -fsS --max-time 15 "$DEPLOY_HEALTH_URL" >/dev/null; then
    die "Health check failed. Inspect: journalctl -u ${DEPLOY_SERVICE} -n 80 --no-pager"
  fi
  log "Health check OK."

  log "Waiting for readiness: GET ${DEPLOY_READY_URL} (timeout ${DEPLOY_READY_TIMEOUT}s)"
  elapsed=0
  while [[ "$elapsed" -lt "$DEPLOY_READY_TIMEOUT" ]]; do
    if curl -fsS --max-time 15 "$DEPLOY_READY_URL" >/dev/null; then
      log "Readiness check OK."
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  die "Readiness check timed out after ${DEPLOY_READY_TIMEOUT}s. Inspect: journalctl -u ${DEPLOY_SERVICE} -n 80 --no-pager"
}

restart_service
smoke_ready

log "Deploy finished: ${DEPLOY_REF} is ready."
