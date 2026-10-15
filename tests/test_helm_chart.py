"""Helm chart render checks.

Skipped locally when ``helm`` is not on ``PATH`` unless
``KEYSTONE_REQUIRE_HELM=1`` (CI sets this in the ``helm`` job).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from support.env_vars import environment_md_variables

REPO_ROOT = Path(__file__).resolve().parents[1]
CHART_DIR = REPO_ROOT / "charts" / "keystone-mcp"
K8S_EXAMPLE = REPO_ROOT / "examples" / "kubernetes" / "deployment.yaml"
ENVIRONMENT_DOC = REPO_ROOT / "docs" / "environment.md"

_HELM = shutil.which("helm")
_REQUIRE_HELM = os.environ.get("KEYSTONE_REQUIRE_HELM") == "1"
_SKIP_REASON = "helm not found on PATH (install helm or set KEYSTONE_REQUIRE_HELM=1 in CI)"


def _helm_available() -> bool:
    return _HELM is not None


pytestmark = [
    pytest.mark.skipif(not _helm_available() and not _REQUIRE_HELM, reason=_SKIP_REASON),
    pytest.mark.skipif(not _helm_available() and _REQUIRE_HELM, reason=_SKIP_REASON),
]


def _helm_template(
    *extra_values: Path | str,
    extra_set: tuple[str, ...] = (),
    expect_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        _HELM or "helm",
        "template",
        "test",
        str(CHART_DIR),
        "-f",
        str(CHART_DIR / "ci" / "default-values.yaml"),
    ]
    for item in extra_values:
        cmd.extend(["-f", str(item)])
    for pair in extra_set:
        cmd.extend(["--set", pair])
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if expect_failure:
        assert result.returncode != 0, result.stdout
    else:
        assert result.returncode == 0, result.stderr or result.stdout
    return result


def _documents(text: str) -> list[dict[str, Any]]:
    return list(yaml.safe_load_all(text))


def _deployment(docs: list[dict[str, Any]]) -> dict[str, Any]:
    for doc in docs:
        if doc and doc.get("kind") == "Deployment":
            return doc
    raise AssertionError("no Deployment in render output")


def _container(deployment: dict[str, Any]) -> dict[str, Any]:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    return containers[0]


def test_default_render_matches_example_security():
    result = _helm_template()
    deployment = _deployment(_documents(result.stdout))
    example = yaml.safe_load(K8S_EXAMPLE.read_text(encoding="utf-8"))
    ex_container = example["spec"]["template"]["spec"]["containers"][0]
    container = _container(deployment)

    ex_pod = example["spec"]["template"]["spec"]
    pod = deployment["spec"]["template"]["spec"]
    assert pod["securityContext"] == ex_pod["securityContext"]
    assert container["securityContext"] == ex_container["securityContext"]
    assert pod["terminationGracePeriodSeconds"] == ex_pod["terminationGracePeriodSeconds"]
    assert pod["automountServiceAccountToken"] is False

    mount_names = {m["name"] for m in container["volumeMounts"] if m["mountPath"] == "/tmp"}
    assert mount_names
    volumes = deployment["spec"]["template"]["spec"]["volumes"]
    tmp_vol = next(v for v in volumes if v["name"] in mount_names)
    assert "emptyDir" in tmp_vol

    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    startup = container["startupProbe"]
    ex_startup = ex_container["startupProbe"]
    assert startup["httpGet"] == ex_startup["httpGet"]
    assert startup["periodSeconds"] == ex_startup["periodSeconds"]
    assert startup["failureThreshold"] == ex_startup["failureThreshold"]


def test_image_tag_defaults_to_chart_app_version():
    result = _helm_template()
    deployment = _deployment(_documents(result.stdout))
    chart = yaml.safe_load((CHART_DIR / "Chart.yaml").read_text(encoding="utf-8"))
    image = _container(deployment)["image"]
    assert image.endswith(f":{chart['appVersion']}")


def test_policy_tools_read_only_without_claim():
    result = _helm_template()
    deployment = _deployment(_documents(result.stdout))
    env = {
        item["name"]: item.get("value")
        for item in _container(deployment).get("env", [])
        if "name" in item
    }
    assert env.get("KEYSTONE_MCP_POLICY_TOOLS") == "read-only"


def test_full_policy_tools_requires_claim():
    result = _helm_template(extra_set=("rbac.policyTools=full",), expect_failure=True)
    combined = (result.stderr + result.stdout).lower()
    assert "existingpolicyclaim" in combined.replace("_", "").replace(
        "-", ""
    ) or "existingPolicyClaim" in (result.stderr + result.stdout)


def test_base_url_required():
    result = _helm_template(extra_set=("baseUrl=",), expect_failure=True)
    assert "baseUrl" in (result.stderr + result.stdout)


def test_secret_required():
    result = subprocess.run(
        [
            _HELM or "helm",
            "template",
            "test",
            str(CHART_DIR),
            "--set",
            "baseUrl=https://mcp.example.com",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "existingSecret" in (result.stderr + result.stdout) or "secret.create" in (
        result.stderr + result.stdout
    )


def test_ingress_host_must_match_base_url():
    result = _helm_template(
        extra_set=(
            "ingress.enabled=true",
            "ingress.host=wrong.example.com",
        ),
        expect_failure=True,
    )
    assert "ingress.host" in (result.stderr + result.stdout) or "baseUrl" in (
        result.stderr + result.stdout
    )


def test_configmap_checksum_only_for_login_providers():
    without = _helm_template()
    dep_without = _deployment(_documents(without.stdout))
    ann_without = dep_without["spec"]["template"]["metadata"].get("annotations") or {}
    assert "checksum/config" not in ann_without

    with_providers = _helm_template(
        extra_set=("loginProviders=version: 1\nproviders: []\n",),
    )
    dep_with = _deployment(_documents(with_providers.stdout))
    ann_with = dep_with["spec"]["template"]["metadata"].get("annotations") or {}
    assert "checksum/login-providers" in ann_with
    assert "checksum/config" not in ann_with


def test_values_schema_rejects_unknown_profile():
    result = subprocess.run(
        [
            _HELM or "helm",
            "lint",
            str(CHART_DIR),
            "--strict",
            "-f",
            str(CHART_DIR / "ci" / "default-values.yaml"),
            "--set",
            "profile=staging",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "profile" in (result.stderr + result.stdout).lower()


def test_env_names_are_known_variables():
    result = _helm_template()
    deployment = _deployment(_documents(result.stdout))
    container = _container(deployment)
    known = environment_md_variables(ENVIRONMENT_DOC)
    names: set[str] = set()
    for item in container.get("env", []):
        name = item.get("name")
        if name and name.startswith("KEYSTONE_MCP_"):
            names.add(name)
    for block in container.get("envFrom", []):
        if "secretRef" in block:
            continue
    unknown = names - known
    assert not unknown, f"unknown KEYSTONE_MCP_* in Deployment: {sorted(unknown)}"


def test_helm_lint_ci_values():
    for path in sorted((CHART_DIR / "ci").glob("*.yaml")):
        proc = subprocess.run(
            [_HELM or "helm", "lint", str(CHART_DIR), "--strict", "-f", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
