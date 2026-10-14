"""Static checks on the GitHub Actions workflow files (second-review finding 13).

Guards against three regressions, all found in review and all invisible to a
human skim of a long YAML file:

* every workflow file still parses as YAML;
* ``ci.yml`` and ``release.yml`` declare a restrictive top-level
  ``permissions`` block (``contents: read``), so a job added later without
  its own ``permissions:`` does not inherit the repository's default token
  scope (which can be broader, e.g. ``write`` for both ``contents`` and
  ``packages`` on a repo that has not opted into the restrictive default);
  jobs that need more (``publish``'s ``packages: write``,
  ``github-release``'s ``contents: write``) still declare it themselves;
* every third-party action is pinned to a 40-hex-character commit SHA
  rather than a mutable tag (``@v7`` can be force-moved to point at
  different code without this repository noticing) — and specifically,
  ``aquasecurity/trivy-action`` is pinned to the *commit* v0.36.0's tag
  points at, not to the SHA of the annotated tag object itself (a tag
  object has its own SHA, distinct from, and not resolvable by GitHub's
  Actions runner as, the commit it annotates).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"
WORKFLOW_FILES = sorted(WORKFLOWS_DIR.glob("*.yml"))

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# The commit aquasecurity/trivy-action's v0.36.0 tag points at (verified via
# `gh api repos/aquasecurity/trivy-action/git/ref/tags/v0.36.0` ->
# object.sha (a tag object) -> `gh api .../git/tags/<that sha>` ->
# object.sha, a commit).
_TRIVY_ACTION_V0_36_0_COMMIT_SHA = "ed142fd0673e97e23eac54620cfb913e5ce36c25"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS_DIR / name).read_text(encoding="utf-8"))


def _iter_uses(doc: dict):
    for job in doc.get("jobs", {}).values():
        steps = job.get("steps")
        if not steps:
            continue
        for step in steps:
            uses = step.get("uses")
            if uses:
                yield uses


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=[p.name for p in WORKFLOW_FILES])
def test_workflow_file_parses_as_yaml(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    assert "jobs" in doc


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=[p.name for p in WORKFLOW_FILES])
def test_every_third_party_action_is_pinned_to_a_commit_sha(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    for uses in _iter_uses(doc):
        if uses.startswith("./"):
            continue  # a local reusable workflow, not a third-party action
        owner_repo, _, ref = uses.partition("@")
        assert ref, f"{path.name}: '{uses}' has no @ref"
        assert _COMMIT_SHA_RE.match(ref), (
            f"{path.name}: '{owner_repo}' is pinned to '{ref}', not a 40-character commit SHA"
        )


def test_trivy_action_is_pinned_to_the_commit_not_the_tag_object():
    doc = _load("security.yml")
    for uses in _iter_uses(doc):
        if uses.startswith("aquasecurity/trivy-action@"):
            _, _, ref = uses.partition("@")
            assert ref == _TRIVY_ACTION_V0_36_0_COMMIT_SHA, (
                "aquasecurity/trivy-action must be pinned to the commit its "
                "version tag points at, not to the SHA of the tag object itself"
            )
            return
    pytest.fail("aquasecurity/trivy-action step not found in security.yml")


@pytest.mark.parametrize("name", ["ci.yml", "release.yml"])
def test_workflow_declares_a_restrictive_top_level_permissions_block(name: str):
    doc = _load(name)
    assert doc.get("permissions") == {"contents": "read"}, (
        f"{name} must declare 'permissions: contents: read' at the top level; "
        "jobs that need more scope add it on the job itself"
    )


def test_release_job_permissions_are_not_widened_by_the_top_level_block():
    doc = _load("release.yml")
    jobs = doc["jobs"]
    assert jobs["image-build"]["permissions"] == {"contents": "read", "packages": "write"}
    assert jobs["image-scan"]["permissions"] == {"contents": "read", "packages": "read"}
    assert jobs["image-smoke"]["permissions"] == {"contents": "read", "packages": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "read", "packages": "write"}
    assert jobs["github-release"]["permissions"] == {"contents": "write"}
    # wheel-smoke only installs and probes the already-built wheel: no job
    # permissions of its own, so it inherits the restrictive top-level
    # 'contents: read' instead of whatever the repository's default token
    # scope happens to be.
    assert "permissions" not in jobs["wheel-smoke"]
    # pypi needs no repository contents beyond read and exchanges its OIDC
    # token for a PyPI one (trusted publishing) via id-token: write.
    assert jobs["pypi"]["permissions"] == {"contents": "read", "id-token": "write"}


def _find_trivy_step(doc: dict) -> dict:
    for job in doc.get("jobs", {}).values():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("aquasecurity/trivy-action@"):
                return step
    raise AssertionError("no aquasecurity/trivy-action step found")


@pytest.mark.parametrize("name", ["security.yml", "release.yml"])
def test_trivy_scan_step_is_blocking(name: str):
    """A fixable HIGH/CRITICAL finding must fail the job, in both workflows (Z10).

    ``continue-on-error`` would make the step always report success whatever
    Trivy finds, and ``exit-code``/``trivyignores`` control whether a finding
    is treated as a failure at all and where the accepted exceptions live.
    """
    doc = _load(name)
    step = _find_trivy_step(doc)
    assert "continue-on-error" not in step, (
        f"{name}: the Trivy step must not set 'continue-on-error' — a "
        "fixable HIGH/CRITICAL finding must fail the job, not just be reported"
    )
    with_block = step.get("with", {})
    assert with_block.get("exit-code") == "1", (
        f'{name}: the Trivy step must set exit-code: "1" so a finding fails the step'
    )
    assert with_block.get("trivyignores") == ".trivyignore", (
        f"{name}: the Trivy step must read temporary exceptions from .trivyignore"
    )


def _job_needs(doc: dict, job_name: str) -> list[str]:
    needs = doc["jobs"][job_name].get("needs")
    if needs is None:
        return []
    return [needs] if isinstance(needs, str) else list(needs)


def test_release_scans_the_pushed_digest_for_each_platform():
    doc = _load("release.yml")
    scan = doc["jobs"]["image-scan"]
    platforms = scan["strategy"]["matrix"]["platform"]
    assert platforms == ["linux/amd64", "linux/arm64"]
    raw = (WORKFLOWS_DIR / "release.yml").read_text(encoding="utf-8")
    assert "needs.image-build.outputs.digest" in raw
    step = _find_trivy_step_in_job(scan)
    assert "needs.image-build.outputs.digest" in str(step.get("with", {}))


def _find_trivy_step_in_job(job: dict) -> dict:
    for step in job.get("steps") or []:
        if str(step.get("uses", "")).startswith("aquasecurity/trivy-action@"):
            return step
    raise AssertionError("no aquasecurity/trivy-action step found in job")


def test_release_publish_does_not_build():
    """Tagged releases must tag an already-built digest, not rebuild the image."""
    raw = (WORKFLOWS_DIR / "release.yml").read_text(encoding="utf-8")
    publish_block = raw.split("  publish:", 1)[1].split("\n  pypi:", 1)[0]
    assert "docker/build-push-action" not in publish_block
    assert "imagetools create" in publish_block
    assert "needs.image-build.outputs.digest" in publish_block
    doc = _load("release.yml")
    needs = _job_needs(doc, "publish")
    assert "image-scan" in needs
    assert "image-smoke" in needs


def test_release_checks_published_digest():
    raw = (WORKFLOWS_DIR / "release.yml").read_text(encoding="utf-8")
    assert "imagetools inspect" in raw
    assert "needs.image-build.outputs.digest" in raw


def test_latest_tag_is_conditional():
    raw = (WORKFLOWS_DIR / "release.yml").read_text(encoding="utf-8")
    assert "type=raw,value=latest,enable=" in raw


def test_workflow_dispatch_has_no_unused_inputs():
    doc = _load("release.yml")
    on_block = doc.get("on") or doc.get(True)  # yaml 1.1 'on' key
    if isinstance(on_block, dict):
        dispatch = on_block.get("workflow_dispatch")
    else:
        dispatch = None
    if dispatch is None:
        return
    inputs = dispatch.get("inputs") or {}
    raw = (WORKFLOWS_DIR / "release.yml").read_text(encoding="utf-8")
    for name in inputs:
        assert f"inputs.{name}" in raw or f"github.event.inputs.{name}" in raw, (
            f"release.yml declares workflow_dispatch input {name!r} but never reads it"
        )


def test_every_setup_uv_step_pins_one_version():
    versions: set[str] = set()
    for path in WORKFLOW_FILES:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in doc.get("jobs", {}).values():
            for step in job.get("steps") or []:
                uses = step.get("uses", "")
                if not str(uses).startswith("astral-sh/setup-uv@"):
                    continue
                version = step.get("with", {}).get("version")
                assert version, f"{path.name}: astral-sh/setup-uv must pin with.version"
                versions.add(str(version))
    assert len(versions) == 1, f"setup-uv version must match everywhere, got {versions!r}"


def test_dependabot_watches_docker():
    dependabot = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / ".github" / "dependabot.yml").read_text(
            encoding="utf-8"
        )
    )
    ecosystems = [entry["package-ecosystem"] for entry in dependabot["updates"]]
    assert "docker" in ecosystems


def test_pr_template_links_are_absolute():
    template = (
        Path(__file__).resolve().parent.parent / ".github" / "pull_request_template.md"
    ).read_text(encoding="utf-8")
    for match in re.finditer(r"\]\(([^)]+)\)", template):
        url = match.group(1)
        if url.startswith("#"):
            continue
        assert url.startswith("https://"), (
            f"PR template link {url!r} must be absolute (https://...)"
        )


def test_release_publish_depends_on_the_image_scan():
    """pypi and github-release only run once publish has succeeded."""
    doc = _load("release.yml")
    assert "publish" in _job_needs(doc, "pypi")
    assert "publish" in _job_needs(doc, "github-release")


def _job_step_names(doc: dict, job_name: str) -> list[str]:
    job = doc["jobs"][job_name]
    return [step.get("name", "") for step in job.get("steps") or []]


def _job_step_run_text(doc: dict, job_name: str) -> str:
    chunks: list[str] = []
    for step in doc["jobs"][job_name].get("steps") or []:
        run = step.get("run")
        if run:
            chunks.append(str(run))
    return "\n".join(chunks)


def test_security_fuzz_nightly_job_runs_marked_tests_with_redis():
    doc = _load("security.yml")
    job = doc["jobs"]["fuzz-nightly"]
    services = job.get("services") or {}
    assert "redis" in services
    env = job.get("env") or {}
    assert env.get("HYPOTHESIS_PROFILE") == "nightly"
    run_text = _job_step_run_text(doc, "fuzz-nightly")
    assert '-m fuzz' in run_text or '-m "fuzz"' in run_text
    assert "tests/security" in run_text


def test_test_job_has_redis_and_postgres_services():
    doc = _load("test-gate.yml")
    test_job = doc["jobs"]["test"]
    services = test_job.get("services") or {}
    assert "redis" in services
    assert "postgres" in services
    env = test_job.get("env") or {}
    assert env.get("KEYSTONE_MCP_REDIS_URL")
    postgres_url = env.get("KEYSTONE_TEST_POSTGRES_URL", "")
    assert postgres_url
    assert "test" in postgres_url.lower()


def test_contract_freeze_step_runs_before_full_suite():
    doc = _load("test-gate.yml")
    names = _job_step_names(doc, "test")
    assert "Contract freeze gate" in names
    assert "Full test suite" in names
    assert names.index("Contract freeze gate") < names.index("Full test suite")

    lint = doc["jobs"]["lint"]
    lint_names = _job_step_names(doc, "lint")
    assert any("Frozen baseline matches" in name for name in lint_names)
    checkout = next(
        step
        for step in lint.get("steps") or []
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout.get("with", {}).get("fetch-depth") == 0


def test_skip_check_step_present():
    doc = _load("test-gate.yml")
    assert "Check skipped tests" in _job_step_names(doc, "test")


def test_canary_runs_daily_with_latest_and_lowest():
    doc = _load("canary.yml")
    on_block = doc.get("on") or doc.get(True)
    schedule = (on_block or {}).get("schedule") or []
    assert schedule, "canary.yml must declare a schedule"
    assert "workflow_dispatch" in (on_block or {})
    assert doc.get("permissions") == {"contents": "read"}
    assert "latest" in doc["jobs"]
    assert "lowest-direct" in doc["jobs"]
    latest_run = _job_step_run_text(doc, "latest")
    assert "uv lock --upgrade" in latest_run


def test_plugin_template_job_installs_with_dependencies():
    doc = _load("ci.yml")
    run_text = _job_step_run_text(doc, "plugin-template")
    assert "--no-deps" not in run_text


def test_coverage_threshold_is_enforced():
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = re.search(r"fail_under\s*=\s*(\d+)", pyproject)
    assert match is not None
    assert int(match.group(1)) >= 85
    gate = _load("test-gate.yml")
    full_suite = next(
        step
        for step in gate["jobs"]["test"].get("steps") or []
        if step.get("name") == "Full test suite"
    )
    assert "--cov" in str(full_suite.get("run", ""))
