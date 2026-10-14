"""Behaviour of scripts/deploy.sh with stubbed git, uv, systemctl, sudo, curl."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = ROOT / "scripts" / "deploy.sh"


pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None,
    reason="bash is required to exercise deploy.sh",
)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _deploy_harness(tmp_path: Path) -> tuple[Path, Path, dict[str, Path]]:
    """Return (repo_root, call_log, stub_paths)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    logs = tmp_path / "logs"
    logs.mkdir()
    call_log = logs / "calls.log"

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    git_log = logs / "git.log"
    uv_log = logs / "uv.log"
    curl_log = logs / "curl.log"
    systemctl_log = logs / "systemctl.log"

    _write_executable(
        bin_dir / "git",
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            printf '%s\\n' "git $*" >> "{git_log}"
            while [[ "$1" == "-C" ]]; do shift 2; done
            cmd="$1"
            shift || true
            case "$cmd" in
              rev-parse)
                if [[ "${{1:-}}" == "--is-inside-work-tree" ]]; then
                  if [[ "${{GIT_INSIDE_WORK_TREE:-1}}" == "1" ]]; then exit 0; fi
                  exit 1
                fi
                if [[ "${{1:-}}" == "--short" && "${{2:-}}" == "HEAD" ]]; then echo abc1234; exit 0; fi
                if [[ "${{1:-}}" == "-q" && "${{2:-}}" == "--verify" ]]; then
                  ref="${{3#refs/tags/}}"
                  if [[ "$ref" == "${{DEPLOY_REF:-}}" && "${{GIT_TAG_EXISTS:-0}}" == "1" ]]; then
                    exit 0
                  fi
                  exit 1
                fi
                ;;
              fetch|checkout|pull)
                exit 0
                ;;
            esac
            exit 0
            """
        ),
    )

    _write_executable(
        bin_dir / "uv",
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            printf '%s\\n' "uv $*" >> "{uv_log}"
            exit 0
            """
        ),
    )

    _write_executable(
        bin_dir / "curl",
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            printf '%s\\n' "curl $*" >> "{curl_log}"
            url="${{@: -1}}"
            if [[ "$url" == *"/healthz"* ]]; then
              exit 0
            fi
            if [[ "$url" == *"/readyz"* ]]; then
              count="$(grep -c readyz "{curl_log}" 2>/dev/null || true)"
              ready_failures="${{CURL_READY_FAILURES:-0}}"
              if (( count <= ready_failures )); then
                exit 22
              fi
              exit 0
            fi
            exit 0
            """
        ),
    )

    _write_executable(
        bin_dir / "sudo",
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            if [[ "${{1:-}}" == "-n" && "${{2:-}}" == "true" ]]; then exit 0; fi
            printf '%s\\n' "sudo $*" >> "{systemctl_log}"
            exec "$@"
            """
        ),
    )

    _write_executable(
        bin_dir / "systemctl",
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            printf '%s\\n' "systemctl $*" >> "{systemctl_log}"
            exit 0
            """
        ),
    )

    (repo / ".git").mkdir()
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(DEPLOY_SCRIPT, repo / "scripts" / "deploy.sh")

    stubs = {
        "git": git_log,
        "uv": uv_log,
        "curl": curl_log,
        "systemctl": systemctl_log,
    }
    return repo, call_log, stubs


def _run_deploy(repo: Path, bin_dir: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if "DEPLOY_REF" not in env:
        merged.pop("DEPLOY_REF", None)
    merged.update(env)
    merged["PATH"] = f"{bin_dir}:{merged.get('PATH', '')}"
    return subprocess.run(
        ["bash", "scripts/deploy.sh"],
        cwd=repo,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


def test_tag_ref_is_checked_out_detached(tmp_path: Path) -> None:
    repo, _, stubs = _deploy_harness(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run_deploy(
        repo,
        bin_dir,
        {"DEPLOY_REF": "v0.6.0", "GIT_TAG_EXISTS": "1"},
    )
    assert result.returncode == 0, result.stderr + result.stdout
    git_calls = stubs["git"].read_text(encoding="utf-8")
    assert "git checkout --detach v0.6.0" in git_calls
    assert "git pull" not in git_calls


def test_branch_ref_pulls_fast_forward(tmp_path: Path) -> None:
    repo, _, stubs = _deploy_harness(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run_deploy(repo, bin_dir, {"DEPLOY_REF": "main", "GIT_TAG_EXISTS": "0"})
    assert result.returncode == 0, result.stderr + result.stdout
    git_calls = stubs["git"].read_text(encoding="utf-8")
    assert "git checkout main" in git_calls
    assert "git pull --ff-only origin main" in git_calls
    assert "--detach" not in git_calls


def test_deploy_branch_is_a_deprecated_alias(tmp_path: Path) -> None:
    repo, _, _ = _deploy_harness(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run_deploy(
        repo,
        bin_dir,
        {"DEPLOY_BRANCH": "release/0.6", "GIT_TAG_EXISTS": "0"},
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "DEPLOY_BRANCH is deprecated, use DEPLOY_REF" in result.stderr


def test_missing_git_clone_fails(tmp_path: Path) -> None:
    repo, _, _ = _deploy_harness(tmp_path)
    shutil.rmtree(repo / ".git")
    bin_dir = tmp_path / "bin"
    result = _run_deploy(repo, bin_dir, {"GIT_INSIDE_WORK_TREE": "0"})
    assert result.returncode != 0
    assert "docs/deploy.md" in result.stderr + result.stdout


def test_waits_for_readyz(tmp_path: Path) -> None:
    repo, _, stubs = _deploy_harness(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run_deploy(
        repo,
        bin_dir,
        {"DEPLOY_REF": "main", "GIT_TAG_EXISTS": "0", "CURL_READY_FAILURES": "2"},
    )
    assert result.returncode == 0, result.stderr + result.stdout
    ready_calls = [
        line for line in stubs["curl"].read_text(encoding="utf-8").splitlines() if "readyz" in line
    ]
    assert len(ready_calls) == 3


def test_readyz_timeout_fails(tmp_path: Path) -> None:
    repo, _, _ = _deploy_harness(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run_deploy(
        repo,
        bin_dir,
        {
            "DEPLOY_REF": "main",
            "GIT_TAG_EXISTS": "0",
            "CURL_READY_FAILURES": "999",
            "DEPLOY_READY_TIMEOUT": "3",
        },
    )
    assert result.returncode != 0
    assert "journalctl" in result.stderr


def test_uv_sync_is_not_editable(tmp_path: Path) -> None:
    repo, _, stubs = _deploy_harness(tmp_path)
    bin_dir = tmp_path / "bin"
    result = _run_deploy(
        repo,
        bin_dir,
        {"DEPLOY_REF": "main", "GIT_TAG_EXISTS": "0", "SKIP_RESTART": "1"},
    )
    assert result.returncode == 0, result.stderr + result.stdout
    uv_calls = stubs["uv"].read_text(encoding="utf-8")
    assert "uv sync --locked --no-dev --no-editable" in uv_calls
