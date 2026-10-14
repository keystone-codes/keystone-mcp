"""Tests for ``setup.sh``'s non-interactive mode (A07).

Every test copies ``setup.sh``, ``.env.example`` and ``config/rbac-policy.yaml``
into an isolated ``tmp_path`` and runs
``bash setup.sh --non-interactive --skip-install`` there, with a clean
environment (no ``KEYSTONE_MCP_*``/``KEYSTONE_SETUP_*`` leaking in from the
developer's own shell). The module is skipped entirely on a platform without
``bash``; Redis is read from ``KEYSTONE_MCP_REDIS_URL`` in the *test's*
environment (the same variable the rest of the suite uses) and the whole
module is skipped if it is unset or unreachable.

``KEYSTONE_MCP_USERS_DB_URL`` and ``KEYSTONE_MCP_RBAC_POLICY_PATH`` are
compared by resolved path rather than raw string: on macOS, a bare
``subprocess.run(cwd=...)`` with no inherited ``$PWD`` makes bash resolve its
working directory through ``getcwd()``, which can canonicalize a symlinked
temp dir (``/var`` -> ``/private/var``) differently from how pytest's
``tmp_path`` spells it.
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

from keystone_mcp.config import load_settings
from keystone_mcp.env_file import load_env_file
from support.test_env import require_redis_url

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETUP_SCRIPT = PROJECT_ROOT / "setup.sh"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
RBAC_POLICY = PROJECT_ROOT / "config" / "rbac-policy.yaml"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not available")


@pytest.fixture
def redis_url() -> str:
    url = require_redis_url()
    parsed = urlparse(url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 6379), timeout=2):
            pass
    except OSError:
        pytest.skip(f"Redis at {url} is not reachable")
    return url


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    shutil.copy(SETUP_SCRIPT, tmp_path / "setup.sh")
    shutil.copy(ENV_EXAMPLE, tmp_path / ".env.example")
    (tmp_path / "config").mkdir()
    shutil.copy(RBAC_POLICY, tmp_path / "config" / "rbac-policy.yaml")
    return tmp_path


def run_setup(
    sandbox: Path,
    env: dict[str, str],
    *,
    args: tuple[str, ...] = ("--non-interactive", "--skip-install"),
) -> subprocess.CompletedProcess[str]:
    full_env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", str(sandbox))}
    full_env.update(env)
    return subprocess.run(
        ["bash", "setup.sh", *args],
        cwd=sandbox,
        env=full_env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )


def local_env(redis_url: str, **overrides: str) -> dict[str, str]:
    env = {
        "KEYSTONE_SETUP_PROFILE": "local",
        "KEYSTONE_SETUP_ADMIN_EMAIL": "Admin@Example.com",
        "KEYSTONE_SETUP_ADMIN_TOKEN": "a-local-admin-token",
        "KEYSTONE_SETUP_REDIS_URL": redis_url,
    }
    env.update(overrides)
    return env


def production_env(redis_url: str, **overrides: str) -> dict[str, str]:
    env = {
        "KEYSTONE_SETUP_PROFILE": "production",
        "KEYSTONE_SETUP_ADMIN_EMAIL": "Admin@Example.com",
        "KEYSTONE_SETUP_BASE_URL": "https://mcp.example.com",
        "KEYSTONE_SETUP_GOOGLE_CLIENT_ID": "a-client-id",
        "KEYSTONE_SETUP_GOOGLE_CLIENT_SECRET": "a-client-secret",
        "KEYSTONE_SETUP_USERS_DB_URL": "postgresql+psycopg://keystone:pw@db:5432/keystone",
        "KEYSTONE_SETUP_REDIS_URL": redis_url,
    }
    env.update(overrides)
    return env


def parse_dotenv(path: Path) -> dict[str, str]:
    """Only active (uncommented) ``KEY=VALUE`` lines, the way the server reads them."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key] = value
    return values


def active_keys(path: Path) -> list[str]:
    return [
        line.split("=", 1)[0]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    ]


def assert_sqlite_points_inside(db_url: str, directory: Path) -> None:
    assert db_url.startswith("sqlite:////"), db_url
    file_path = Path(db_url[len("sqlite:///") :])
    assert file_path.is_absolute()
    assert file_path.resolve().parent == directory.resolve()
    assert file_path.name == "keystone-users.db"


def test_local_profile_writes_expected_env(sandbox, redis_url):
    result = run_setup(sandbox, local_env(redis_url))
    assert result.returncode == 0, result.stdout + result.stderr

    env_path = sandbox / ".env"
    values = parse_dotenv(env_path)

    assert values["KEYSTONE_MCP_DEPLOYMENT_PROFILE"] == "local"
    assert values["KEYSTONE_MCP_BASE_URL"] == "http://localhost:8080"
    assert values["KEYSTONE_MCP_ENABLED_LOGIN_METHODS"] == "api_key"
    assert values["KEYSTONE_MCP_PRIMARY_LOGIN_METHOD"] == "api_key"
    assert values["KEYSTONE_MCP_DEV_TOKENS"] == "a-local-admin-token"
    assert values["KEYSTONE_MCP_GOOGLE_CLIENT_ID"] == ""
    assert values["KEYSTONE_MCP_GOOGLE_CLIENT_SECRET"] == ""
    assert values["KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN"] == ""
    assert values["KEYSTONE_MCP_RBAC_MODE"] == "enforce"
    assert (
        Path(values["KEYSTONE_MCP_RBAC_POLICY_PATH"]).resolve()
        == (sandbox / "config" / "rbac-policy.yaml").resolve()
    )
    assert values["KEYSTONE_MCP_REDIS_URL"] == redis_url
    assert values["KEYSTONE_MCP_USERS_BACKEND"] == "local"
    assert_sqlite_points_inside(values["KEYSTONE_MCP_USERS_DB_URL"], sandbox)
    assert values["KEYSTONE_MCP_SUPERADMIN_EMAIL"] == "admin@example.com"
    assert values["KEYSTONE_MCP_USERS_SERVICE_URL"] == ""
    assert values["KEYSTONE_MCP_USERS_SERVICE_TOKEN"] == ""
    assert values["KEYSTONE_MCP_AUTH_SERVICE_URL"] == ""
    assert values["KEYSTONE_MCP_AUTH_SERVICE_TOKEN"] == ""
    assert values["KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"]

    # Every variable setup.sh writes appears exactly once among the active
    # lines: it replaces the existing (section-1) line in place and never
    # also uncomments/duplicates the matching commented-out section-2 default
    # (decision S11).
    keys = active_keys(env_path)
    assert len(keys) == len(set(keys)), keys

    mode = stat.S_IMODE(env_path.stat().st_mode)
    assert mode == 0o600


def test_production_profile_writes_expected_env(sandbox, redis_url):
    result = run_setup(sandbox, production_env(redis_url))
    assert result.returncode == 0, result.stdout + result.stderr

    env_path = sandbox / ".env"
    values = parse_dotenv(env_path)

    assert values["KEYSTONE_MCP_DEPLOYMENT_PROFILE"] == "production"
    assert values["KEYSTONE_MCP_BASE_URL"] == "https://mcp.example.com"
    assert values["KEYSTONE_MCP_ENABLED_LOGIN_METHODS"] == "google"
    assert values["KEYSTONE_MCP_PRIMARY_LOGIN_METHOD"] == "google"
    assert values["KEYSTONE_MCP_DEV_TOKENS"] == ""
    assert values["KEYSTONE_MCP_GOOGLE_CLIENT_ID"] == "a-client-id"
    assert values["KEYSTONE_MCP_GOOGLE_CLIENT_SECRET"] == "a-client-secret"
    assert values["KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN"] == ""
    assert values["KEYSTONE_MCP_RBAC_MODE"] == "enforce"
    assert (
        Path(values["KEYSTONE_MCP_RBAC_POLICY_PATH"]).resolve()
        == (sandbox / "config" / "rbac-policy.yaml").resolve()
    )
    assert values["KEYSTONE_MCP_REDIS_URL"] == redis_url
    assert values["KEYSTONE_MCP_USERS_BACKEND"] == "local"
    assert (
        values["KEYSTONE_MCP_USERS_DB_URL"] == "postgresql+psycopg://keystone:pw@db:5432/keystone"
    )
    assert values["KEYSTONE_MCP_SUPERADMIN_EMAIL"] == "admin@example.com"
    assert values["KEYSTONE_MCP_USERS_SERVICE_URL"] == ""
    assert values["KEYSTONE_MCP_USERS_SERVICE_TOKEN"] == ""
    assert values["KEYSTONE_MCP_AUTH_SERVICE_URL"] == ""
    assert values["KEYSTONE_MCP_AUTH_SERVICE_TOKEN"] == ""
    assert values["KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"]

    keys = active_keys(env_path)
    assert len(keys) == len(set(keys)), keys

    mode = stat.S_IMODE(env_path.stat().st_mode)
    assert mode == 0o600


@pytest.mark.parametrize(
    "profile,missing_var",
    [
        ("local", "KEYSTONE_SETUP_PROFILE"),
        ("local", "KEYSTONE_SETUP_ADMIN_EMAIL"),
        ("local", "KEYSTONE_SETUP_ADMIN_TOKEN"),
        ("local", "KEYSTONE_SETUP_REDIS_URL"),
        ("production", "KEYSTONE_SETUP_PROFILE"),
        ("production", "KEYSTONE_SETUP_ADMIN_EMAIL"),
        ("production", "KEYSTONE_SETUP_BASE_URL"),
        ("production", "KEYSTONE_SETUP_GOOGLE_CLIENT_ID"),
        ("production", "KEYSTONE_SETUP_GOOGLE_CLIENT_SECRET"),
        ("production", "KEYSTONE_SETUP_USERS_DB_URL"),
        ("production", "KEYSTONE_SETUP_REDIS_URL"),
    ],
)
def test_missing_answer_exits_with_code_2(sandbox, redis_url, profile, missing_var):
    env = local_env(redis_url) if profile == "local" else production_env(redis_url)
    del env[missing_var]

    result = run_setup(sandbox, env)

    assert result.returncode == 2, result.stdout + result.stderr
    assert missing_var in result.stderr


def test_production_requires_https_base_url(sandbox, redis_url):
    env = production_env(redis_url, KEYSTONE_SETUP_BASE_URL="http://mcp.example.com")

    result = run_setup(sandbox, env)

    assert result.returncode != 0
    assert "https://" in result.stderr
    assert not (sandbox / ".env").exists()


def test_production_requires_postgres_url(sandbox, redis_url):
    env = production_env(redis_url, KEYSTONE_SETUP_USERS_DB_URL="sqlite:///x.db")

    result = run_setup(sandbox, env)

    assert result.returncode != 0
    assert "postgresql+psycopg://" in result.stderr
    assert not (sandbox / ".env").exists()


def test_rerun_keeps_audit_salt(sandbox, redis_url):
    env = local_env(redis_url)

    first = run_setup(sandbox, env)
    assert first.returncode == 0, first.stdout + first.stderr
    salt_1 = parse_dotenv(sandbox / ".env")["KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"]

    second = run_setup(sandbox, env)
    assert second.returncode == 0, second.stdout + second.stderr
    salt_2 = parse_dotenv(sandbox / ".env")["KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"]

    assert salt_1 == salt_2
    # Still exactly one of each, after a second write over the first.
    keys = active_keys(sandbox / ".env")
    assert len(keys) == len(set(keys)), keys


def test_without_terminal_and_flag_exits_with_code_1(sandbox):
    full_env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", str(sandbox))}
    result = subprocess.run(
        ["bash", "setup.sh", "--skip-install"],
        cwd=sandbox,
        env=full_env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1


@pytest.mark.parametrize("profile", ["local", "production"])
def test_written_env_passes_validate_settings(sandbox, redis_url, monkeypatch, profile):
    env = local_env(redis_url) if profile == "local" else production_env(redis_url)
    result = run_setup(sandbox, env)
    assert result.returncode == 0, result.stdout + result.stderr

    monkeypatch.chdir(sandbox)
    file_environ: dict[str, str] = {}
    load_env_file(environ=file_environ)
    written = {k: v for k, v in file_environ.items() if k.startswith("KEYSTONE_MCP_")}
    assert written, "load_env_file did not pick up any KEYSTONE_MCP_* variable from .env"
    for key, value in written.items():
        monkeypatch.setenv(key, value)

    settings = load_settings()  # raises ConfigError on any inconsistency

    assert settings.deployment_profile == profile


# ── Second review: control-character injection, credential redaction, .env
# permissions (A07 follow-up) ────────────────────────────────────────────────


def test_local_profile_rejects_newline_in_admin_token(sandbox, redis_url):
    """A newline in a ``KEYSTONE_SETUP_*`` value must not let an attacker splice
    extra ``KEYSTONE_MCP_*`` lines into ``.env`` (the value is spliced in as
    ``lines[index] = f"{key}={value}"``, so an embedded ``\\n`` becomes a real
    line break once the list is joined and written out)."""
    env = local_env(redis_url, KEYSTONE_SETUP_ADMIN_TOKEN="tok\nKEYSTONE_MCP_RBAC_MODE=disabled")

    result = run_setup(sandbox, env)

    assert result.returncode == 2, result.stdout + result.stderr
    assert not (sandbox / ".env").exists()


def test_local_profile_rejects_carriage_return_in_admin_email(sandbox, redis_url):
    env = local_env(redis_url, KEYSTONE_SETUP_ADMIN_EMAIL="admin@example.com\r")

    result = run_setup(sandbox, env)

    assert result.returncode == 2, result.stdout + result.stderr
    assert not (sandbox / ".env").exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"KEYSTONE_SETUP_BASE_URL": "https://x\nKEYSTONE_MCP_DEPLOYMENT_PROFILE=local"},
        {"KEYSTONE_SETUP_GOOGLE_CLIENT_ID": "a-client-id\nKEYSTONE_MCP_RBAC_MODE=disabled"},
        {"KEYSTONE_SETUP_GOOGLE_CLIENT_SECRET": "a-secret\nKEYSTONE_MCP_RBAC_MODE=disabled"},
        {"KEYSTONE_SETUP_GOOGLE_ALLOWED_DOMAIN": "example.com\nKEYSTONE_MCP_RBAC_MODE=disabled"},
        {
            "KEYSTONE_SETUP_USERS_DB_URL": (
                "postgresql+psycopg://u:p@h/db\nKEYSTONE_MCP_RBAC_MODE=disabled"
            )
        },
    ],
    ids=[
        "base_url",
        "google_client_id",
        "google_client_secret",
        "google_allowed_domain",
        "users_db_url",
    ],
)
def test_production_profile_rejects_control_chars_in_every_field(sandbox, redis_url, overrides):
    env = production_env(redis_url, **overrides)

    result = run_setup(sandbox, env)

    assert result.returncode == 2, result.stdout + result.stderr
    assert not (sandbox / ".env").exists()


def test_redis_url_rejects_control_chars(sandbox, redis_url):
    env = local_env(
        redis_url, KEYSTONE_SETUP_REDIS_URL=f"{redis_url}\nKEYSTONE_MCP_RBAC_MODE=disabled"
    )

    result = run_setup(sandbox, env)

    assert result.returncode == 2, result.stdout + result.stderr
    assert not (sandbox / ".env").exists()


def test_control_char_injection_does_not_modify_an_existing_env(sandbox, redis_url):
    """An injection attempt on a *second* run (one where ``.env`` already
    exists from a prior successful run) must leave that file byte-for-byte
    unchanged, not just refuse to create a fresh one."""
    first = run_setup(sandbox, local_env(redis_url))
    assert first.returncode == 0, first.stdout + first.stderr
    env_path = sandbox / ".env"
    before = env_path.read_bytes()
    mode_before = stat.S_IMODE(env_path.stat().st_mode)

    injected = local_env(
        redis_url, KEYSTONE_SETUP_ADMIN_TOKEN="tok\nKEYSTONE_MCP_RBAC_MODE=disabled"
    )
    result = run_setup(sandbox, injected)

    assert result.returncode == 2, result.stdout + result.stderr
    assert env_path.read_bytes() == before
    assert stat.S_IMODE(env_path.stat().st_mode) == mode_before


def test_postgres_url_credentials_are_redacted_on_schema_error(sandbox, redis_url):
    """The wrong-scheme error for ``KEYSTONE_SETUP_USERS_DB_URL`` must not leak
    the password onto stderr (it previously echoed the URL verbatim, got
    '<url-with-password>')."""
    secret = "pg_super_secret_pw"  # noqa: S105 - test fixture value, not a real credential
    bad_url = f"postgres://keystone:{secret}@db:5432/keystone"
    env = production_env(redis_url, KEYSTONE_SETUP_USERS_DB_URL=bad_url)

    result = run_setup(sandbox, env)

    assert result.returncode != 0
    assert secret not in result.stderr
    assert "***" in result.stderr
    assert not (sandbox / ".env").exists()


def test_env_file_is_never_readable_beyond_owner_while_being_written(sandbox, redis_url):
    """``cp .env.example .env`` used to create the file at mode 0644 and only
    ``chmod``ed it to 0600 after the secrets were already written into it.
    Poll the file's mode while setup.sh runs under a wide-open process umask:
    it must never be observed wider than 0600."""
    env = local_env(redis_url)
    full_env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", str(sandbox))}
    full_env.update(env)
    env_path = sandbox / ".env"
    observed_modes: set[int] = set()

    proc = subprocess.Popen(
        ["bash", "setup.sh", "--non-interactive", "--skip-install"],
        cwd=sandbox,
        env=full_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=lambda: os.umask(0),
    )
    try:
        deadline = time.monotonic() + 30
        while proc.poll() is None and time.monotonic() < deadline:
            if env_path.exists():
                try:
                    observed_modes.add(stat.S_IMODE(env_path.stat().st_mode))
                except OSError:
                    pass
            time.sleep(0.0005)
        stdout, stderr = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()

    assert proc.returncode == 0, stdout + stderr
    if env_path.exists():
        observed_modes.add(stat.S_IMODE(env_path.stat().st_mode))
    assert observed_modes, "never observed .env while setup.sh ran"
    assert all(mode & 0o077 == 0 for mode in observed_modes), observed_modes


def test_rerun_does_not_loosen_existing_env_permissions(sandbox, redis_url):
    env = local_env(redis_url)
    first = run_setup(sandbox, env)
    assert first.returncode == 0, first.stdout + first.stderr
    env_path = sandbox / ".env"
    os.chmod(env_path, 0o600)

    second = run_setup(sandbox, env)

    assert second.returncode == 0, second.stdout + second.stderr
    mode = stat.S_IMODE(env_path.stat().st_mode)
    assert mode == 0o600
