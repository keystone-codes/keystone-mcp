#!/usr/bin/env python3
"""Live upgrade stand: 0.4.0 → 0.5.0 → current, rollback, mixed replicas."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml
from helpers import (
    ADMIN_EMAIL,
    TokenPair,
    call_tool,
    discover_oauth_metadata,
    http_client,
    list_tool_names,
    oauth_login_pair,
    parse_users_list_result,
    redis_hashed_access_key,
    redis_plain_access_key,
    refresh_tokens,
    tool_diff,
)

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
COMPOSE_FILE = ROOT / "compose.yml"
ARTIFACTS = ROOT / "artifacts"

BASE_URL = os.environ.get("UPGRADE_BASE_URL", "http://127.0.0.1:18080")
ALT_BASE_URL = os.environ.get("UPGRADE_ALT_BASE_URL", "http://127.0.0.1:18081")

IMAGE_040 = os.environ.get(
    "UPGRADE_IMAGE_040", "ghcr.io/keystone-codes/keystone-mcp:0.4.0"
)
IMAGE_050 = os.environ.get(
    "UPGRADE_IMAGE_050", "ghcr.io/keystone-codes/keystone-mcp:0.5.0"
)
IMAGE_CURRENT = os.environ.get("KEYSTONE_IMAGE", "keystone-mcp:upgrade-current")

MEMBER_EMAIL = "member@upgrade.test"
VIEWER_EMAIL = "viewer@upgrade.test"
BLOCKED_EMAIL = "blocked@upgrade.test"


@dataclass
class StandState:
    admin_tokens: TokenPair | None = None
    member_tokens: TokenPair | None = None
    catalog_tools_040: list[str] = field(default_factory=list)
    catalog_tools_050: list[str] = field(default_factory=list)
    oauth_metadata: dict[str, Any] | None = None
    service_account_name: str = "upgrade-bot"
    api_key_secret: str | None = None


class Runner:
    def __init__(self) -> None:
        self.state = StandState()
        self.failures: list[str] = []

    def step(self, name: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"ok {name}")
        else:
            msg = f"FAIL {name}"
            if detail:
                msg = f"{msg}: {detail}"
            print(msg)
            self.failures.append(name)

    def compose(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), *args]
        merged = os.environ.copy()
        merged.setdefault("KEYSTONE_IMAGE", IMAGE_CURRENT)
        merged.setdefault("KEYSTONE_ENV_FILE", "env/current.env")
        if env:
            merged.update(env)
        return subprocess.run(
            cmd,
            cwd=ROOT,
            env=merged,
            text=True,
            capture_output=True,
            check=False,
        )

    def ensure_image(self, tag: str, *, git_commit: str | None = None) -> bool:
        local = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True,
            text=True,
            check=False,
        )
        if local.returncode == 0:
            return True
        inspect = subprocess.run(
            ["docker", "manifest", "inspect", tag],
            capture_output=True,
            text=True,
            check=False,
        )
        if inspect.returncode == 0:
            return True
        build_dir: Path | None = None
        if git_commit:
            build_dir = ARTIFACTS / "image-build" / git_commit
            if build_dir.exists():
                import shutil

                shutil.rmtree(build_dir)
            build_dir.mkdir(parents=True, exist_ok=True)
            archive = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "archive", git_commit],
                capture_output=True,
                check=False,
            )
            if archive.returncode != 0:
                return False
            extract = subprocess.run(
                ["tar", "-x", "-C", str(build_dir)],
                input=archive.stdout,
                check=False,
            )
            if extract.returncode != 0:
                return False
            context = str(build_dir)
        else:
            context = str(REPO_ROOT)
        print(f"building image {tag} from {context}")
        build = subprocess.run(["docker", "build", "-t", tag, context], check=False)
        return build.returncode == 0

    def down(self) -> None:
        self.compose("down", "-v", "--remove-orphans")

    def up_keystone(self, image: str, env_file: str, *, alt: bool = False) -> None:
        service = "keystone-alt" if alt else "keystone"
        env = {
            "KEYSTONE_IMAGE" if not alt else "KEYSTONE_ALT_IMAGE": image,
            "KEYSTONE_ENV_FILE" if not alt else "KEYSTONE_ALT_ENV_FILE": env_file,
        }
        if alt:
            self.compose("--profile", "mixed", "up", "-d", service, env=env)
        else:
            self.compose("up", "-d", service, env={**env, "KEYSTONE_IMAGE": image, "KEYSTONE_ENV_FILE": env_file})

    def wait_ready(self, base_url: str, timeout: float = 180.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = httpx.get(f"{base_url}/readyz", timeout=5.0)
                if resp.status_code == 200 and resp.json().get("status") == "ok":
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(2.0)
        return False

    def exec_cli(self, *args: str, env_file: str = "env/current.env", image: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {"KEYSTONE_ENV_FILE": env_file}
        if image:
            env["KEYSTONE_IMAGE"] = image
        return self.compose("exec", "-T", "keystone", "keystone-mcp", *args, env=env)

    def run_cli_oneoff(self, *args: str, env_file: str, image: str) -> subprocess.CompletedProcess[str]:
        return self.compose(
            "run",
            "--rm",
            "-T",
            "keystone",
            "keystone-mcp",
            *args,
            env={"KEYSTONE_IMAGE": image, "KEYSTONE_ENV_FILE": env_file},
        )

    def snapshot_artifacts(self, label: str) -> None:
        dest = ARTIFACTS / label
        dest.mkdir(parents=True, exist_ok=True)
        pg_schema = self.compose(
            "exec",
            "-T",
            "postgres",
            "pg_dump",
            "-U",
            "keystone",
            "-s",
            "keystone",
        )
        if pg_schema.returncode == 0:
            (dest / "schema.sql").write_text(pg_schema.stdout, encoding="utf-8")
        pg_data = self.compose(
            "exec",
            "-T",
            "postgres",
            "pg_dump",
            "-U",
            "keystone",
            "-a",
            "keystone",
        )
        if pg_data.returncode == 0:
            (dest / "data.sql").write_text(pg_data.stdout, encoding="utf-8")
        redis_keys = self.compose("exec", "-T", "redis", "redis-cli", "--scan")
        if redis_keys.returncode == 0:
            lines = []
            for key in redis_keys.stdout.splitlines():
                key = key.strip()
                if not key:
                    continue
                key_type = self.compose("exec", "-T", "redis", "redis-cli", "TYPE", key)
                ttl = self.compose("exec", "-T", "redis", "redis-cli", "TTL", key)
                lines.append(
                    f"{key}\t{(key_type.stdout or '').strip()}\t{(ttl.stdout or '').strip()}"
                )
            (dest / "redis-keys.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    async def seed_users(self, base_url: str) -> bool:
        async with http_client() as client:
            self.state.oauth_metadata = await discover_oauth_metadata(client, base_url)
            self.state.admin_tokens = await oauth_login_pair(client, base_url, ADMIN_EMAIL)
            for email, roles in (
                (MEMBER_EMAIL, ["member"]),
                (VIEWER_EMAIL, ["viewer"]),
                (BLOCKED_EMAIL, ["member"]),
            ):
                await call_tool(
                    base_url,
                    self.state.admin_tokens.access_token,
                    "users_add",
                    {
                        "email": email,
                        "full_name": email.split("@")[0],
                        "roles": roles,
                    },
                )
            await call_tool(
                base_url,
                self.state.admin_tokens.access_token,
                "users_block",
                {"email": BLOCKED_EMAIL},
            )
            self.state.member_tokens = await oauth_login_pair(client, base_url, MEMBER_EMAIL)
            self.state.catalog_tools_040 = await list_tool_names(
                base_url, self.state.admin_tokens.access_token
            )
        return True

    def load_expected(self, key: str) -> dict[str, list[dict[str, str]]]:
        raw = yaml.safe_load((ROOT / "expected_diffs.yaml").read_text(encoding="utf-8"))
        return raw[key]

    async def verify_cross_version(
        self,
        base_url: str,
        *,
        label: str,
        diff_key: str | None,
        previous_tools: list[str],
        db_revision: str | None,
    ) -> bool:
        assert self.state.member_tokens and self.state.oauth_metadata
        async with http_client() as client:
            assert self.state.admin_tokens
            tools = await list_tool_names(base_url, self.state.admin_tokens.access_token)
            if diff_key:
                expected = self.load_expected(diff_key)
                bad_removed, bad_added = tool_diff(previous_tools, tools, expected)
                if bad_removed or bad_added:
                    self.step(
                        f"{label} tools/list diff",
                        False,
                        f"unexpected removed={bad_removed} added={bad_added}",
                    )
                    return False
            member_tools = await list_tool_names(
                base_url, self.state.member_tokens.access_token
            )
            refreshed = await refresh_tokens(
                client,
                self.state.oauth_metadata["token_endpoint"],
                client_id=self.state.member_tokens.client_id,
                refresh_token=self.state.member_tokens.refresh_token,
                resource=self.state.oauth_metadata["resource"],
            )
            self.state.member_tokens = refreshed
            tools_after_refresh = await list_tool_names(base_url, refreshed.access_token)
            if set(tools_after_refresh) != set(member_tools):
                self.step(f"{label} refresh preserves tools", False, "tool set changed")
                return False
            users_active = parse_users_list_result(
                await call_tool(
                    base_url,
                    self.state.admin_tokens.access_token,
                    "users_list",
                    {},
                )
            )
            users_blocked = parse_users_list_result(
                await call_tool(
                    base_url,
                    self.state.admin_tokens.access_token,
                    "users_list",
                    {"is_blocked": True},
                )
            )
            users = users_active + users_blocked
            emails = {u.get("email") for u in users}
            for expected_email in (ADMIN_EMAIL, MEMBER_EMAIL, VIEWER_EMAIL, BLOCKED_EMAIL):
                if expected_email not in emails:
                    self.step(f"{label} users_list", False, f"missing {expected_email}")
                    return False
            blocked = next(u for u in users if u.get("email") == BLOCKED_EMAIL)
            if not blocked.get("is_blocked"):
                self.step(f"{label} users_list blocked flag", False, "blocked user not blocked")
                return False
        if db_revision:
            proc = self.compose(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "keystone",
                "-d",
                "keystone",
                "-tAc",
                "SELECT version_num FROM keystone_users_alembic_version;",
            )
            actual = (proc.stdout or "").strip()
            if proc.returncode != 0 or actual != db_revision:
                self.step(
                    f"{label} db revision",
                    False,
                    f"expected {db_revision!r}, got {actual!r}",
                )
                return False
        return True

    async def extend_050(self, base_url: str) -> bool:
        add = self.run_cli_oneoff(
            "service-accounts",
            "add",
            "--name",
            self.state.service_account_name,
            "--description",
            "upgrade stand bot",
            "--role",
            "viewer",
            env_file="env/0.5.0.env",
            image=IMAGE_050,
        )
        if add.returncode != 0:
            return False
        issue = self.run_cli_oneoff(
            "keys",
            "issue",
            "--subject",
            f"svc:{self.state.service_account_name}",
            "--label",
            "upgrade",
            env_file="env/0.5.0.env",
            image=IMAGE_050,
        )
        if issue.returncode != 0:
            return False
        try:
            payload = json.loads(issue.stdout)
        except json.JSONDecodeError:
            return False
        secret = payload.get("key")
        if not isinstance(secret, str) or not secret:
            return False
        self.state.api_key_secret = secret
        return True

    async def verify_current_extras(self, base_url: str) -> bool:
        assert self.state.member_tokens
        async with http_client() as client:
            self.state.oauth_metadata = await discover_oauth_metadata(client, base_url)
            self.state.member_tokens = await refresh_tokens(
                client,
                self.state.oauth_metadata["token_endpoint"],
                client_id=self.state.member_tokens.client_id,
                refresh_token=self.state.member_tokens.refresh_token,
                resource=self.state.oauth_metadata["resource"],
            )
            await list_tool_names(base_url, self.state.member_tokens.access_token)
            await list_tool_names(base_url, self.state.member_tokens.access_token)
        plain = redis_plain_access_key("km:oauth:", self.state.member_tokens.access_token)
        hashed = redis_hashed_access_key("km:oauth:", self.state.member_tokens.access_token)
        plain_check = self.compose("exec", "-T", "redis", "redis-cli", "EXISTS", plain)
        hashed_check = self.compose("exec", "-T", "redis", "redis-cli", "EXISTS", hashed)
        exists_plain = (
            plain_check.returncode == 0 and (plain_check.stdout or "").strip() == "1"
        )
        exists_hashed = (
            hashed_check.returncode == 0 and (hashed_check.stdout or "").strip() == "1"
        )
        if exists_plain:
            return False
        if not exists_hashed:
            return False
        proc = self.run_cli_oneoff(
            "users",
            "db",
            "current",
            env_file="env/current.env",
            image=IMAGE_CURRENT,
        )
        if proc.returncode != 0 or "0004_identity_binding" not in proc.stdout:
            return False
        return True

    async def rollback_scenario(self) -> bool:
        assert self.state.member_tokens and self.state.oauth_metadata
        refresh_before = self.state.member_tokens.refresh_token
        self.compose("stop", "keystone")
        down = self.run_cli_oneoff(
            "users",
            "db",
            "downgrade",
            "--to",
            "0003_api_keys",
            "--yes",
            env_file="env/current.env",
            image=IMAGE_CURRENT,
        )
        if down.returncode != 0:
            return False
        self.up_keystone(IMAGE_050, "env/0.5.0.env")
        if not self.wait_ready(BASE_URL):
            return False
        async with http_client() as client:
            meta = await discover_oauth_metadata(client, BASE_URL)
            resp = await client.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_before,
                    "client_id": self.state.member_tokens.client_id,
                    "resource": meta["resource"],
                },
            )
            if resp.status_code >= 500:
                return False
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if resp.status_code not in (400, 401) or body.get("error") != "invalid_grant":
                return False
            fresh = await oauth_login_pair(client, BASE_URL, MEMBER_EMAIL)
            if not fresh.access_token:
                return False
        proc = self.compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "keystone",
            "-d",
            "keystone",
            "-tAc",
            "SELECT version_num FROM keystone_users_alembic_version;",
        )
        return proc.returncode == 0 and (proc.stdout or "").strip() == "0003_api_keys"

    async def mixed_replicas(self) -> tuple[bool, str]:
        self.compose("stop", "keystone", "keystone-alt")
        self.compose("rm", "-f", "keystone", "keystone-alt")
        rev = self.compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "keystone",
            "-d",
            "keystone",
            "-tAc",
            "SELECT version_num FROM keystone_users_alembic_version;",
        )
        if rev.returncode != 0 or (rev.stdout or "").strip() != "0003_api_keys":
            return False, f"mixed replicas need db 0003, got {(rev.stdout or '').strip()!r}"
        # Start 0.5.x before current migrates the shared database past 0003.
        self.compose(
            "--profile",
            "mixed",
            "up",
            "-d",
            "--force-recreate",
            "keystone-alt",
            env={
                "KEYSTONE_ALT_IMAGE": IMAGE_050,
                "KEYSTONE_ALT_ENV_FILE": "env/0.5.0-alt.env",
            },
        )
        if not self.wait_ready(ALT_BASE_URL):
            return False, "0.5 alt replica not ready"
        try:
            async with http_client() as client:
                meta_alt = await discover_oauth_metadata(client, ALT_BASE_URL)
                pair = await oauth_login_pair(client, ALT_BASE_URL, VIEWER_EMAIL)
                await list_tool_names(ALT_BASE_URL, pair.access_token)
        except Exception as exc:  # noqa: BLE001
            return False, f"alt oauth/tools: {exc}"
        self.compose(
            "up",
            "-d",
            "--force-recreate",
            "keystone",
            env={
                "KEYSTONE_IMAGE": IMAGE_CURRENT,
                "KEYSTONE_ENV_FILE": "env/current.env",
            },
        )
        if not self.wait_ready(BASE_URL):
            return False, "current replica not ready"
        try:
            async with http_client() as client:
                meta_cur = await discover_oauth_metadata(client, BASE_URL)
                refreshed = await refresh_tokens(
                    client,
                    meta_cur["token_endpoint"],
                    client_id=pair.client_id,
                    refresh_token=pair.refresh_token,
                    resource=meta_alt["resource"],
                )
        except Exception as exc:  # noqa: BLE001
            return False, f"current refresh: {exc}"
        async with http_client() as client:
            hashed = redis_hashed_access_key("km:oauth:", refreshed.access_token)
            exists = self.compose("exec", "-T", "redis", "redis-cli", "EXISTS", hashed)
            if exists.returncode != 0 or (exists.stdout or "").strip() != "1":
                return False, "hashed access key missing after current refresh"
            resp = await client.post(
                meta_alt["token_endpoint"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refreshed.refresh_token,
                    "client_id": pair.client_id,
                    "resource": meta_alt["resource"],
                },
            )
            if resp.status_code >= 500:
                return False, f"alt refresh returned {resp.status_code}"
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if resp.status_code not in (400, 401) or body.get("error") != "invalid_grant":
                return False, f"alt refresh expected invalid_grant, got {resp.status_code} {body!r}"
            return True, ""

    def startup_refused_on_newer_db(self) -> bool:
        self.compose("stop", "keystone")
        upgrade = self.compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "keystone",
            "-d",
            "keystone",
            "-c",
            "UPDATE keystone_users_alembic_version SET version_num = '0004_identity_binding';",
        )
        if upgrade.returncode != 0:
            return False
        proc = self.compose(
            "run",
            "--rm",
            "-T",
            "keystone",
            "keystone-mcp",
            "serve",
            env={"KEYSTONE_IMAGE": IMAGE_050, "KEYSTONE_ENV_FILE": "env/0.5.0.env"},
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode != 0 and (
            "Can't locate revision" in combined
            or "users directory database is not ready" in combined
        )


async def async_main() -> int:
    runner = Runner()

    images_ok = (
        runner.ensure_image(IMAGE_050, git_commit="5155209")
        or runner.ensure_image(IMAGE_050)
    ) and (
        runner.ensure_image(IMAGE_040, git_commit="5988b51")
        or runner.ensure_image(IMAGE_040)
    )
    if IMAGE_CURRENT == "keystone-mcp:upgrade-current":
        images_ok = images_ok and runner.ensure_image(IMAGE_CURRENT)
    else:
        images_ok = images_ok and (
            runner.ensure_image(IMAGE_CURRENT) or runner.ensure_image(IMAGE_CURRENT)
        )
    runner.step("ensure images", images_ok)

    runner.down()
    runner.compose("up", "-d", "postgres", "redis", "hello-upstream")

    runner.up_keystone(IMAGE_040, "env/0.4.0.env")
    runner.step("0.4.0 ready", runner.wait_ready(BASE_URL))

    try:
        seeded = await runner.seed_users(BASE_URL)
    except Exception as exc:  # noqa: BLE001
        seeded = False
        runner.step("0.4.0 seed", False, str(exc))
    else:
        runner.step("0.4.0 seed", seeded)

    runner.snapshot_artifacts("0.4.0")

    runner.compose("stop", "keystone")
    runner.up_keystone(IMAGE_050, "env/0.5.0.env")
    runner.step("0.5.0 ready", runner.wait_ready(BASE_URL))
    if runner.state.admin_tokens:
        runner.state.catalog_tools_050 = await list_tool_names(
            BASE_URL, runner.state.admin_tokens.access_token
        )

    ok_050 = False
    try:
        ok_050 = await runner.verify_cross_version(
            BASE_URL,
            label="0.5.0",
            diff_key="0.4.0->0.5.0",
            previous_tools=runner.state.catalog_tools_040,
            db_revision="0003_api_keys",
        )
    except Exception as exc:  # noqa: BLE001
        runner.step("0.5.0 verify", False, str(exc))
    else:
        runner.step("0.5.0 verify", ok_050)

    try:
        extended = await runner.extend_050(BASE_URL)
    except Exception as exc:  # noqa: BLE001
        extended = False
        runner.step("0.5.0 extend", False, str(exc))
    else:
        runner.step("0.5.0 extend", extended)

    runner.snapshot_artifacts("0.5.0")

    runner.compose("stop", "keystone")
    runner.up_keystone(IMAGE_CURRENT, "env/current.env")
    runner.step("current ready", runner.wait_ready(BASE_URL))

    ok_current = False
    try:
        ok_current = await runner.verify_cross_version(
            BASE_URL,
            label="current",
            diff_key="0.5.0->0.6.0",
            previous_tools=runner.state.catalog_tools_050,
            db_revision="0004_identity_binding",
        )
    except Exception as exc:  # noqa: BLE001
        runner.step("current verify", False, str(exc))
    else:
        runner.step("current verify", ok_current)

    try:
        extras = await runner.verify_current_extras(BASE_URL)
    except Exception as exc:  # noqa: BLE001
        extras = False
        runner.step("current hashed keys", False, str(exc))
    else:
        runner.step("current hashed keys", extras)

    runner.snapshot_artifacts("0.6.0")

    try:
        async with http_client() as client:
            assert runner.state.member_tokens and runner.state.oauth_metadata
            runner.state.member_tokens = await refresh_tokens(
                client,
                runner.state.oauth_metadata["token_endpoint"],
                client_id=runner.state.member_tokens.client_id,
                refresh_token=runner.state.member_tokens.refresh_token,
                resource=runner.state.oauth_metadata["resource"],
            )
        rollback_ok = await runner.rollback_scenario()
    except Exception as exc:  # noqa: BLE001
        rollback_ok = False
        runner.step("rollback 0.6→0.5", False, str(exc))
    else:
        runner.step("rollback 0.6→0.5", rollback_ok)

    try:
        mixed_ok, mixed_detail = await runner.mixed_replicas()
    except Exception as exc:  # noqa: BLE001
        mixed_ok = False
        runner.step("mixed replicas", False, str(exc))
    else:
        runner.step("mixed replicas", mixed_ok, mixed_detail)

    runner.step("0.5.0 refuses 0004 db", runner.startup_refused_on_newer_db())

    if runner.failures:
        logs = runner.compose("logs", "--no-color")
        if logs.stdout:
            print(logs.stdout[-8000:], file=sys.stderr)
        if logs.stderr:
            print(logs.stderr[-8000:], file=sys.stderr)
        return 1
    return 0


def main() -> int:
    return asyncio.run(async_main())


if __name__ == "__main__":
    sys.exit(main())
