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
