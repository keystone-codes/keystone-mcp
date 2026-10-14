#!/usr/bin/env bash
# Write .env for one of two deployment profiles, then install dependencies.
#
#   local       token sign-in, SQLite, this machine only (loopback BASE_URL)
#   production  Google sign-in, Postgres, a public host
#
# Does not start the server, create the administrator, or touch the users
# database: the server does all of that at startup, from
# KEYSTONE_MCP_SUPERADMIN_EMAIL (see docs/users.md).
#
# Flags: --non-interactive (read every answer from KEYSTONE_SETUP_* instead of
# prompting), --skip-install (skip "uv sync" / "pip install"), --help.
set -euo pipefail
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"

NON_INTERACTIVE=0
SKIP_INSTALL=0

print_help() {
  cat <<'EOF'
Usage: setup.sh [--non-interactive] [--skip-install] [--help]

Writes .env for one of two profiles and, unless --skip-install is given,
installs dependencies. Never starts the server, never creates the
administrator, never touches the users database: the server does that at
startup, from KEYSTONE_MCP_SUPERADMIN_EMAIL.

Profiles:
  local       token sign-in, SQLite, loopback BASE_URL only
  production  Google sign-in, Postgres, a public host

Flags:
  --non-interactive   take every answer from the KEYSTONE_SETUP_* variables
                       below instead of prompting; exits with code 2 and a
                       message naming the variable when a required one is
                       missing or invalid
  --skip-install      skip "uv sync --extra dev" / "pip install -e ."
  --help              show this help and exit 0

Environment variables read in --non-interactive mode:
  KEYSTONE_SETUP_PROFILE                required; "local" or "production"
  KEYSTONE_SETUP_ADMIN_EMAIL             required; first administrator's email
  KEYSTONE_SETUP_ADMIN_TOKEN             required for "local"; the administrator's sign-in token
  KEYSTONE_SETUP_BASE_URL                required for "production"; must start with https://
  KEYSTONE_SETUP_GOOGLE_CLIENT_ID        required for "production"
  KEYSTONE_SETUP_GOOGLE_CLIENT_SECRET    required for "production"
  KEYSTONE_SETUP_GOOGLE_ALLOWED_DOMAIN   optional; Google Workspace domain
  KEYSTONE_SETUP_USERS_DB_URL            required for "production"; must start with postgresql+psycopg://
  KEYSTONE_SETUP_REDIS_URL               required; redis:// or rediss://, probed; no container is started
EOF
}

for arg in "$@"; do
  case "$arg" in
    --non-interactive)
      NON_INTERACTIVE=1
      ;;
    --skip-install)
      SKIP_INSTALL=1
      ;;
    --help|-h)
      print_help
      exit 0
      ;;
    *)
      echo "Unknown flag: $arg" >&2
      print_help >&2
      exit 2
      ;;
  esac
done

# Exit code for a question that was never answered (or was answered badly):
# 2 in --non-interactive mode (a script or CI job should see this as "fix the
# environment"), 1 interactively (same as every other usage error here).
fail() {
  echo "$1" >&2
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    exit 2
  fi
  exit 1
}

# A value with an embedded newline (or other control character) must never
# reach the ".env" writer below: it builds each line as
# ``lines[index] = f"{key}={value}"`` and joins the whole file with "\n", so
# an embedded "\n" becomes a real line break once written — splicing
# arbitrary extra KEYSTONE_MCP_* assignments into .env. Reject it at the
# point each value is accepted, in both --non-interactive and interactive
# mode, well before anything is ever written.
reject_control_chars() {
  local name="$1" value="$2"
  case "$value" in
    *[$'\x01'-$'\x1f']*|*$'\x7f'*)
      fail "${name} must not contain control characters (newline, carriage return, tab, ...)."
      ;;
  esac
}

# Strip userinfo (user:password) from a URL for display, e.g. in an error
# message — never print a database URL's credentials verbatim.
redact_url() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit, urlunsplit

url = sys.argv[1]
parts = urlsplit(url)
netloc = parts.netloc
if "@" in netloc:
    _userinfo, _, hostport = netloc.rpartition("@")
    netloc = f"***@{hostport}"
print(urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)))
PY
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 3.11 or newer is required." >&2
  exit 1
fi

if [[ "$NON_INTERACTIVE" -eq 0 && ! -t 0 ]]; then
  echo "setup.sh asks questions interactively. Run it in a terminal, or pass" >&2
  echo "--non-interactive with the KEYSTONE_SETUP_* variables (see --help)." >&2
  exit 1
fi

# ── 1. Profile ────────────────────────────────────────────────────────────────
if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  PROFILE="${KEYSTONE_SETUP_PROFILE:-}"
  [[ -n "$PROFILE" ]] || fail "Set KEYSTONE_SETUP_PROFILE to 'local' or 'production'."
else
  echo "Choose a profile."
  echo "  1) local       token sign-in, SQLite, only this computer"
  echo "  2) production  Google sign-in, Postgres"
  read -r -p "Choice [1]: " profile_choice
  profile_choice="${profile_choice:-1}"
  case "$profile_choice" in
    1|local) PROFILE="local" ;;
    2|production) PROFILE="production" ;;
    *) fail "Choose 1 (local) or 2 (production)." ;;
  esac
fi
if [[ "$PROFILE" != "local" && "$PROFILE" != "production" ]]; then
  fail "KEYSTONE_SETUP_PROFILE must be 'local' or 'production'; got '${PROFILE}'."
fi

# ── 2. First administrator ─────────────────────────────────────────────────────
echo
echo "First administrator. This person signs in and manages users over MCP."
if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  ADMIN_EMAIL="${KEYSTONE_SETUP_ADMIN_EMAIL:-}"
  [[ -n "$ADMIN_EMAIL" ]] || fail "Set KEYSTONE_SETUP_ADMIN_EMAIL to the first administrator's email."
else
  read -r -p "Administrator email: " ADMIN_EMAIL
fi
ADMIN_EMAIL="$(printf '%s' "$ADMIN_EMAIL" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$ADMIN_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  fail "KEYSTONE_SETUP_ADMIN_EMAIL must be a full email address; got '${ADMIN_EMAIL}'."
fi

# ── 3. Sign-in, Google and the users database, by profile ────────────────────
ADMIN_TOKEN=""
BASE_URL=""
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""
GOOGLE_ALLOWED_DOMAIN=""
USERS_DB_URL=""

if [[ "$PROFILE" == "local" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    ADMIN_TOKEN="${KEYSTONE_SETUP_ADMIN_TOKEN:-}"
    [[ -n "$ADMIN_TOKEN" ]] || fail "Set KEYSTONE_SETUP_ADMIN_TOKEN (required for the local profile)."
  else
    read -r -s -p "Administrator token: " ADMIN_TOKEN
    echo
    [[ -n "$ADMIN_TOKEN" ]] || fail "The administrator token is required for the local profile."
  fi
  USERS_DB_URL="sqlite:///${SCRIPT_DIR}/keystone-users.db"
else
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    BASE_URL="${KEYSTONE_SETUP_BASE_URL:-}"
    [[ -n "$BASE_URL" ]] || fail "Set KEYSTONE_SETUP_BASE_URL (required for the production profile)."
  else
    read -r -p "Public base URL (https://...): " BASE_URL
    [[ -n "$BASE_URL" ]] || fail "The public base URL is required for the production profile."
  fi
  [[ "$BASE_URL" == https://* ]] || fail "KEYSTONE_SETUP_BASE_URL must start with https://; got '${BASE_URL}'."

  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    GOOGLE_CLIENT_ID="${KEYSTONE_SETUP_GOOGLE_CLIENT_ID:-}"
    [[ -n "$GOOGLE_CLIENT_ID" ]] || fail "Set KEYSTONE_SETUP_GOOGLE_CLIENT_ID (required for the production profile)."
    GOOGLE_CLIENT_SECRET="${KEYSTONE_SETUP_GOOGLE_CLIENT_SECRET:-}"
    [[ -n "$GOOGLE_CLIENT_SECRET" ]] || fail "Set KEYSTONE_SETUP_GOOGLE_CLIENT_SECRET (required for the production profile)."
    GOOGLE_ALLOWED_DOMAIN="${KEYSTONE_SETUP_GOOGLE_ALLOWED_DOMAIN:-}"
  else
    read -r -p "Google client id: " GOOGLE_CLIENT_ID
    [[ -n "$GOOGLE_CLIENT_ID" ]] || fail "The Google client id is required for the production profile."
    read -r -s -p "Google client secret: " GOOGLE_CLIENT_SECRET
    echo
    [[ -n "$GOOGLE_CLIENT_SECRET" ]] || fail "The Google client secret is required for the production profile."
    read -r -p "Google Workspace domain (empty to allow any): " GOOGLE_ALLOWED_DOMAIN
  fi

  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    USERS_DB_URL="${KEYSTONE_SETUP_USERS_DB_URL:-}"
    [[ -n "$USERS_DB_URL" ]] || fail "Set KEYSTONE_SETUP_USERS_DB_URL (required for the production profile)."
  else
    read -r -p "Users database (postgresql+psycopg://...): " USERS_DB_URL
    [[ -n "$USERS_DB_URL" ]] || fail "The users database URL is required for the production profile."
  fi
  [[ "$USERS_DB_URL" == postgresql+psycopg://* ]] || fail "KEYSTONE_SETUP_USERS_DB_URL must start with postgresql+psycopg://; got '$(redact_url "$USERS_DB_URL")'."
fi

# ── Redis (shared helper: read URL from .env, build URL, probe, display) ─────
redis_py() {
  python3 - "$@" <<'REDIS_PY'
import os
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

COMPOSE_PLACEHOLDER = "redis://redis:6379/0"
CONNECT_TIMEOUT = 3.0


def read_env_redis_url() -> str | None:
    path = Path(".env")
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("KEYSTONE_MCP_REDIS_URL="):
            value = stripped[len("KEYSTONE_MCP_REDIS_URL=") :]
            if value == COMPOSE_PLACEHOLDER or not value.strip():
                return None
            return value
    return None


def parse_redis_url(url: str):
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("redis", "rediss"):
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port if parsed.port is not None else 6379
    path = (parsed.path or "/0").lstrip("/")
    db = path.split("/", 1)[0] if path else "0"
    user = unquote(parsed.username) if parsed.username is not None else ""
    password = unquote(parsed.password) if parsed.password is not None else ""
    has_password = parsed.password is not None and parsed.password != ""
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "db": db,
        "user": user,
        "password": password,
        "has_password": has_password,
    }


def format_host_for_url(host: str) -> str:
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def build_redis_url(host: str, port: int, db: int, user: str, password: str) -> str:
    host_part = format_host_for_url(host)
    user_enc = quote(user, safe="")
    pass_enc = quote(password, safe="")
    if user and password:
        auth = f"{user_enc}:{pass_enc}@"
    elif password:
        auth = f":{pass_enc}@"
    elif user:
        auth = f"{user_enc}@"
    else:
        auth = ""
    return f"redis://{auth}{host_part}:{port}/{db}"


def validate_full_url(url: str) -> str:
    url = url.strip()
    info = parse_redis_url(url)
    if not info:
        print("URL must use redis:// or rediss:// and include a hostname.", file=sys.stderr)
        sys.exit(1)
    return url


def display_info(url: str) -> None:
    info = parse_redis_url(url)
    if not info:
        print("invalid", file=sys.stderr)
        sys.exit(1)
    pw = "password set" if info["has_password"] else "no password"
    print(f"{info['host']}:{info['port']}/{info['db']} ({pw})")


def _recv_line(sock: socket.socket) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\r\n" in data:
            break
    return data.split(b"\r\n", 1)[0]


def _send_cmd(sock: socket.socket, *parts: str) -> bytes:
    payload = b"*" + str(len(parts)).encode() + b"\r\n"
    for part in parts:
        bpart = part.encode()
        payload += b"$" + str(len(bpart)).encode() + b"\r\n" + bpart + b"\r\n"
    sock.sendall(payload)
    return _recv_line(sock)


def probe_redis(url: str) -> int:
    """Return 0 ok, 1 connection, 2 auth."""
    info = parse_redis_url(url)
    if not info:
        return 1
    host = info["host"]
    port = info["port"]
    use_tls = info["scheme"] == "rediss"
    try:
        raw = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except OSError:
        return 1
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.settimeout(CONNECT_TIMEOUT)
        user = info["user"]
        password = info["password"]
        if info["user"] or info["has_password"]:
            if info["user"]:
                reply = _send_cmd(sock, "AUTH", user, password)
            else:
                reply = _send_cmd(sock, "AUTH", password)
            reply_s = reply.decode(errors="replace")
            if reply_s.startswith("-NOAUTH") or reply_s.startswith("-WRONGPASS"):
                return 2
            if reply_s.startswith("-ERR"):
                low = reply_s.lower()
                if "auth" in low or "acl" in low or "password" in low:
                    return 2
                return 1
            if not reply_s.startswith("+OK"):
                if reply_s.startswith("-"):
                    low = reply_s.lower()
                    if "noauth" in low or "wrongpass" in low or "auth" in low:
                        return 2
                return 1
        ping = _send_cmd(sock, "PING")
        if ping == b"+PONG":
            return 0
        ping_s = ping.decode(errors="replace")
        if ping_s.startswith("-NOAUTH") or ping_s.startswith("-WRONGPASS"):
            return 2
        if ping_s.startswith("-ERR"):
            low = ping_s.lower()
            if "auth" in low or "acl" in low:
                return 2
        return 1
    except (OSError, ssl.SSLError, socket.timeout):
        return 1
    finally:
        try:
            raw.close()
        except OSError:
            pass


def tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def cmd_read_url():
    u = read_env_redis_url()
    if u:
        print(u)


def cmd_display():
    display_info(sys.argv[2])


def cmd_validate_url():
    print(validate_full_url(sys.argv[2]))


def cmd_build():
    host = sys.argv[2]
    port = int(sys.argv[3])
    db = int(sys.argv[4])
    user = sys.argv[5]
    password = sys.argv[6]
    if port < 1 or port > 65535:
        print("Port must be between 1 and 65535.", file=sys.stderr)
        sys.exit(1)
    if db < 0:
        print("Database number must be non-negative.", file=sys.stderr)
        sys.exit(1)
    print(build_redis_url(host, port, db, user, password))


def cmd_probe():
    sys.exit(probe_redis(sys.argv[2]))


def cmd_tcp_open():
    host, port = sys.argv[2], int(sys.argv[3])
    sys.exit(0 if tcp_open(host, port) else 1)


def main():
    if len(sys.argv) < 2:
        sys.exit(2)
    cmd = sys.argv[1]
    dispatch = {
        "read_url": cmd_read_url,
        "display": cmd_display,
        "validate_url": cmd_validate_url,
        "build": cmd_build,
        "probe": cmd_probe,
        "tcp_open": cmd_tcp_open,
    }
    fn = dispatch.get(cmd)
    if not fn:
        sys.exit(2)
    fn()


if __name__ == "__main__":
    main()
REDIS_PY
}

redis_probe_url() {
  redis_py probe "$1"
}

redis_prompt_existing_fields() {
  local attempt=1
  local max_attempts=3
  local url host port db user password full_url probe_status
  while [[ "$attempt" -le "$max_attempts" ]]; do
    read -r -p "Full redis:// URL (empty to enter host and port): " full_url
    full_url="$(echo -n "$full_url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -n "$full_url" ]]; then
      url="$(redis_py validate_url "$full_url")"
    else
      read -r -p "Redis host [127.0.0.1]: " host
      host="${host:-127.0.0.1}"
      read -r -p "Redis port [6379]: " port
      port="${port:-6379}"
      read -r -p "Redis database number [0]: " db
      db="${db:-0}"
      read -r -p "Redis ACL username (empty if not used): " user
      read -r -s -p "Redis password (empty if none): " password
      echo
      if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        echo "Port must be an integer from 1 to 65535." >&2
        exit 1
      fi
      if ! [[ "$db" =~ ^[0-9]+$ ]]; then
        echo "Database number must be a non-negative integer." >&2
        exit 1
      fi
      if ! url="$(redis_py build "$host" "$port" "$db" "$user" "$password")"; then
        exit 1
      fi
    fi

    set +e
    redis_probe_url "$url"
    probe_status=$?
    set -e
    case "$probe_status" in
      0)
        REDIS_URL="$url"
        return 0
        ;;
      1)
        echo "Could not connect to Redis. Check host and port." >&2
        attempt=$((attempt + 1))
        ;;
      2)
        echo "Redis authentication failed. Check username and password." >&2
        attempt=$((attempt + 1))
        ;;
      *)
        echo "Redis probe failed." >&2
        attempt=$((attempt + 1))
        ;;
    esac
  done
  exit 1
}

redis_start_local_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to start a local Redis. Re-run and choose an existing Redis, or install Docker." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "The Docker daemon is not reachable. Start Docker and try again." >&2
    exit 1
  fi

  if docker ps -a --format '{{.Names}}' | grep -qx 'keystone-redis'; then
    if ! docker start keystone-redis 2>docker-redis-start.err; then
      cat docker-redis-start.err >&2
      rm -f docker-redis-start.err
      exit 1
    fi
    rm -f docker-redis-start.err
  elif redis_py tcp_open 127.0.0.1 6379; then
    echo "Port 6379 on 127.0.0.1 is already in use." >&2
    echo "Choose an existing Redis at 127.0.0.1 port 6379, or free the port." >&2
    return 2
  else
    if ! docker run -d --name keystone-redis -p 127.0.0.1:6379:6379 redis:7 2>docker-redis-run.err; then
      cat docker-redis-run.err >&2
      rm -f docker-redis-run.err
      exit 1
    fi
    rm -f docker-redis-run.err
  fi

  REDIS_URL="redis://127.0.0.1:6379/0"
  local waited=0 probe_status
  while [[ "$waited" -lt 15 ]]; do
    set +e
    redis_probe_url "$REDIS_URL"
    probe_status=$?
    set -e
    if [[ "$probe_status" -eq 0 ]]; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "Redis container keystone-redis did not answer." >&2
  exit 1
}

redis_show_root_menu_no_url() {
  echo
  echo "Keystone stores OAuth sessions and login-pending state in Redis."
  echo "  1) Use an existing Redis (host, port, password)"
  echo "  2) Start Redis locally with Docker (container keystone-redis on 127.0.0.1:6379)"
}

redis_root_menu_no_url() {
  local default_choice="1" redis_choice local_status
  if command -v docker >/dev/null 2>&1; then
    default_choice="2"
  fi
  redis_show_root_menu_no_url
  read -r -p "Choice [${default_choice}]: " redis_choice
  redis_choice="${redis_choice:-$default_choice}"
  case "$redis_choice" in
    1|existing)
      redis_prompt_existing_fields
      ;;
    2|local|docker)
      local_status=0
      redis_start_local_docker || local_status=$?
      if [[ "$local_status" -eq 2 ]]; then
        redis_show_root_menu_no_url
        read -r -p "Choice: " redis_choice
        case "$redis_choice" in
          1|existing)
            redis_prompt_existing_fields
            ;;
          2|local|docker)
            if redis_py tcp_open 127.0.0.1 6379 && ! docker ps -a --format '{{.Names}}' | grep -qx 'keystone-redis'; then
              echo "Port 6379 is still in use and container keystone-redis does not exist." >&2
              exit 1
            fi
            redis_start_local_docker
            ;;
          *)
            echo "Choose 1 (existing Redis) or 2 (local Docker)." >&2
            exit 1
            ;;
        esac
      fi
      ;;
    *)
      echo "Choose 1 (existing Redis) or 2 (local Docker)." >&2
      exit 1
      ;;
  esac
}

redis_configure() {
  local existing
  existing="$(redis_py read_url || true)"
  if [[ -n "$existing" ]]; then
    local info_line keep_failures=0
    info_line="$(redis_py display "$existing")"
    while true; do
      echo
      echo "Current Redis: ${info_line}."
      echo "  1) Keep current settings"
      echo "  2) Enter a different Redis"
      echo "  3) Use local Docker Redis (container keystone-redis)"
      read -r -p "Choice [1]: " redis_choice
      redis_choice="${redis_choice:-1}"
      case "$redis_choice" in
        1)
          local st
          set +e
          redis_probe_url "$existing"
          st=$?
          set -e
          if [[ "$st" -eq 0 ]]; then
            REDIS_URL="$existing"
            return 0
          fi
          echo "Could not reach Redis with the current settings." >&2
          keep_failures=$((keep_failures + 1))
          if [[ "$keep_failures" -ge 2 ]]; then
            exit 1
          fi
          ;;
        2)
          redis_prompt_existing_fields
          return 0
          ;;
        3)
          local local_status=0
          redis_start_local_docker || local_status=$?
          if [[ "$local_status" -eq 2 ]]; then
            redis_show_root_menu_no_url
            read -r -p "Choice: " retry_choice
            case "$retry_choice" in
              1)
                redis_prompt_existing_fields
                return 0
                ;;
              2)
                if redis_py tcp_open 127.0.0.1 6379 && ! docker ps -a --format '{{.Names}}' | grep -qx 'keystone-redis'; then
                  echo "Port 6379 is still in use and container keystone-redis does not exist." >&2
                  exit 1
                fi
                redis_start_local_docker
                return 0
                ;;
              *)
                echo "Choose 1 (existing Redis) or 2 (local Docker)." >&2
                exit 1
                ;;
            esac
          fi
          return 0
          ;;
        *)
          echo "Choose 1, 2, or 3." >&2
          exit 1
          ;;
      esac
    done
  else
    redis_root_menu_no_url
  fi
}

redis_configure_non_interactive() {
  local url="${KEYSTONE_SETUP_REDIS_URL:-}" probe_status
  [[ -n "$url" ]] || fail "Set KEYSTONE_SETUP_REDIS_URL (redis:// or rediss://)."
  url="$(redis_py validate_url "$url")" || exit 1
  set +e
  redis_probe_url "$url"
  probe_status=$?
  set -e
  case "$probe_status" in
    0)
      REDIS_URL="$url"
      ;;
    1)
      echo "Could not connect to Redis at KEYSTONE_SETUP_REDIS_URL. Check host and port." >&2
      exit 1
      ;;
    2)
      echo "Redis authentication failed for KEYSTONE_SETUP_REDIS_URL. Check username and password." >&2
      exit 1
      ;;
    *)
      echo "Redis probe failed for KEYSTONE_SETUP_REDIS_URL." >&2
      exit 1
      ;;
  esac
}

if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  redis_configure_non_interactive
else
  redis_configure
fi

if [[ -z "${REDIS_URL:-}" ]]; then
  echo "Redis URL was not configured." >&2
  exit 1
fi

# Final gate before anything touches .env: every value collected above (in
# either mode — interactively typed or read from KEYSTONE_SETUP_*) must be
# free of control characters. See reject_control_chars's definition for why.
for _field_name in PROFILE ADMIN_EMAIL ADMIN_TOKEN BASE_URL GOOGLE_CLIENT_ID \
  GOOGLE_CLIENT_SECRET GOOGLE_ALLOWED_DOMAIN USERS_DB_URL REDIS_URL; do
  reject_control_chars "$_field_name" "${!_field_name}"
done

# ── Write .env ────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  # Create the file with 0600 from its very first byte: the cp below would
  # otherwise create it at the process umask's default (typically 0644), and
  # the secrets this script writes next would sit in a group/other-readable
  # file until the chmod at the end of the Python block.
  ( umask 077 && cp .env.example .env )
else
  # An existing .env (e.g. from a prior run) must not be made any more
  # permissive than it already is while we rewrite it.
  chmod 600 .env
fi

POLICY_PATH="${SCRIPT_DIR}/config/rbac-policy.yaml"
PROVIDERS_PATH="${SCRIPT_DIR}/login-providers.yaml"
export PROFILE ADMIN_EMAIL ADMIN_TOKEN BASE_URL GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET \
  GOOGLE_ALLOWED_DOMAIN USERS_DB_URL POLICY_PATH REDIS_URL PROVIDERS_PATH
if [[ "$PROFILE" == "production" ]]; then
  python3 - <<'PY'
import os
import sys
from pathlib import Path

path = Path(os.environ["PROVIDERS_PATH"])
domain = os.environ.get("GOOGLE_ALLOWED_DOMAIN", "").strip()
lines = [
    "version: 1",
    "providers:",
    "  - name: google",
    "    type: google",
    f"    client_id: {os.environ['GOOGLE_CLIENT_ID']}",
    "    client_secret_env: KEYSTONE_MCP_LOGIN_GOOGLE_SECRET",
]
if domain:
    lines.append(f"    allowed_domain: {domain}")
desired = "\n".join(lines) + "\n"
if path.exists():
    existing = path.read_text(encoding="utf-8")
    if existing != desired:
        print(
            f"login-providers.yaml already exists at {path} with different content; leaving it unchanged.",
            file=sys.stderr,
        )
else:
    path.write_text(desired, encoding="utf-8")
    os.chmod(path, 0o600)
PY
fi
python3 - <<'PY'
import ipaddress
import os
import secrets
from pathlib import Path
from urllib.parse import urlparse

path = Path(".env")
text = path.read_text() if path.exists() else ""


def current(key: str) -> str:
    prefix = key + "="
    for line in text.splitlines():
        stripped = line.strip()
        body = stripped[2:].lstrip() if stripped.startswith("#") else stripped
        if body.startswith(prefix):
            return body[len(prefix) :]
    return ""


def is_loopback_host(host: str) -> bool:
    value = host.strip().lower()
    if value == "localhost" or value.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


profile = os.environ["PROFILE"]

if profile == "local":
    current_base_url = current("KEYSTONE_MCP_BASE_URL")
    host = urlparse(current_base_url).hostname or "" if current_base_url else ""
    if current_base_url and is_loopback_host(host):
        base_url = current_base_url
    else:
        base_url = "http://localhost:8080"
else:
    base_url = os.environ["BASE_URL"]

values = {
    "KEYSTONE_MCP_DEPLOYMENT_PROFILE": profile,
    "KEYSTONE_MCP_BASE_URL": base_url,
    "KEYSTONE_MCP_DEV_TOKENS": os.environ.get("ADMIN_TOKEN", "") if profile == "local" else "",
    "KEYSTONE_MCP_RBAC_MODE": "enforce",
    "KEYSTONE_MCP_RBAC_POLICY_PATH": os.environ["POLICY_PATH"],
    "KEYSTONE_MCP_REDIS_URL": os.environ["REDIS_URL"],
    "KEYSTONE_MCP_USERS_BACKEND": "local",
    "KEYSTONE_MCP_USERS_DB_URL": os.environ["USERS_DB_URL"],
    "KEYSTONE_MCP_SUPERADMIN_EMAIL": os.environ["ADMIN_EMAIL"],
}
if profile == "production":
    values["KEYSTONE_MCP_LOGIN_PROVIDERS_PATH"] = str(
        Path(os.environ["PROVIDERS_PATH"]).resolve()
    )
    values["KEYSTONE_MCP_LOGIN_GOOGLE_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET", "")

if not current("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"):
    values["KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"] = secrets.token_hex(32)

lines = text.splitlines()
seen = set()
for index, line in enumerate(lines):
    stripped = line.strip()
    body = stripped[2:].lstrip() if stripped.startswith("#") else stripped
    for key, value in values.items():
        if key in seen:
            # .env.example has a commented-out duplicate of this key in its
            # production section (same name, different default); only the
            # first occurrence (the active one in section 1) is replaced, so
 # one variable never ends up written twice.
            continue
        if body.startswith(key + "="):
            lines[index] = f"{key}={value}"
            seen.add(key)
            break
missing = [f"{key}={value}" for key, value in values.items() if key not in seen]
if missing:
    if lines and lines[-1] != "":
        lines.append("")
    lines.append("# First administrator, written by setup.sh")
    lines.extend(missing)
path.write_text("\n".join(lines) + "\n")
os.chmod(path, 0o600)
PY

# ── Install ───────────────────────────────────────────────────────────────────
if [[ "$SKIP_INSTALL" -eq 0 ]]; then
  if command -v uv >/dev/null 2>&1; then
    uv sync --extra dev
  else
    python3 -m pip install -e .
  fi
fi
if command -v uv >/dev/null 2>&1; then
  run_hint="uv run python -m keystone_mcp.server"
else
  run_hint="python3 -m keystone_mcp.server"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "Start Keystone from this directory with: ${run_hint}"
echo
if [[ "$PROFILE" == "local" ]]; then
  echo "Sign in as ${ADMIN_EMAIL} with the administrator token. The server creates this administrator on first start."
else
  echo "Register ${BASE_URL}/login/google/callback as the Google redirect URI. Sign in with Google as ${ADMIN_EMAIL}."
fi
echo "Roles and allow patterns can be changed from the agent (policy_* tools); the file is ${POLICY_PATH}."

exit 0
