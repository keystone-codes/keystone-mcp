#!/usr/bin/env bash
# Idempotent deploy: git sync, uv install, optional systemd restart, /healthz smoke.
# Run from the repository root, e.g. ./scripts/deploy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEPLOY_BRANCH="${DEPLOY_BRANCH:-master}"
DEPLOY_SERVICE="${DEPLOY_SERVICE:-keystone-mcp.service}"
DEPLOY_HEALTH_URL="${DEPLOY_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
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
  if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    log "Syncing git (branch ${DEPLOY_BRANCH})..."
    git fetch origin "$DEPLOY_BRANCH"
    current_branch="$(git rev-parse --abbrev-ref HEAD)"
    if [[ "$current_branch" != "$DEPLOY_BRANCH" ]]; then
      git checkout "$DEPLOY_BRANCH"
    fi
    git pull --ff-only origin "$DEPLOY_BRANCH"
  else
    warn "Not a git clone at ${ROOT}; skipping fetch/pull."
  fi
else
  log "SKIP_GIT=1 — leaving working tree unchanged."
fi

if ! command -v uv >/dev/null 2>&1; then
  die "uv is required (https://docs.astral.sh/uv/)."
fi

log "Installing Python dependencies (uv sync --locked)..."
uv sync --locked

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

smoke_health() {
  if [[ "$SKIP_SMOKE" == "1" || "$SKIP_RESTART" == "1" ]]; then
    [[ "$SKIP_SMOKE" == "1" ]] && log "SKIP_SMOKE=1 — skipping health check."
    return 0
  fi

  log "Smoke check: GET ${DEPLOY_HEALTH_URL}"
  sleep 2
  if curl -fsS --max-time 15 "$DEPLOY_HEALTH_URL" >/dev/null; then
    log "Health check OK."
  else
    die "Health check failed. Inspect: journalctl -u ${DEPLOY_SERVICE} -n 80 --no-pager"
  fi
}

restart_service
smoke_health

log "Deploy finished."
