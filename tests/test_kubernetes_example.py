"""Static checks on the Kubernetes example manifests.

No cluster, no ``kubectl``: these tests only parse YAML with
``yaml.safe_load`` (or ``safe_load_all`` for the multi-document ConfigMap
payload) and check the handful of properties that would otherwise silently
drift -- the pinned image tag, which probe checks which endpoint, the
non-root/read-only security posture, and which files kustomization.yaml
actually applies.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from keystone_mcp import __version__
from keystone_mcp.config import load_settings, startup_warnings
from support.test_env import UNUSED_REDIS_URL

REPO_ROOT = Path(__file__).resolve().parents[1]
K8S_DIR = REPO_ROOT / "examples" / "kubernetes"
PRODUCTION_POLICY = REPO_ROOT / "examples" / "production" / "policy" / "rbac-policy.yaml"
SHIPPED_POLICY = REPO_ROOT / "config" / "rbac-policy.yaml"


def _load(name: str) -> dict[str, Any]:
    return yaml.safe_load((K8S_DIR / name).read_text(encoding="utf-8"))


def _container(deployment: dict[str, Any]) -> dict[str, Any]:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    return containers[0]


def test_kustomization_lists_only_applied_resources():
    kustomization = _load("kustomization.yaml")

    assert kustomization["namespace"] == "keystone"
    resources = set(kustomization["resources"])
    assert resources == {
        "namespace.yaml",
        "configmap.yaml",
        "deployment.yaml",
        "service.yaml",
        "pdb.yaml",
    }
    # Templates, not meant to be applied as-is.
    assert "secret.example.yaml" not in resources
    assert "ingress.example.yaml" not in resources
    assert "networkpolicy.example.yaml" not in resources


def test_every_manifest_file_parses():
    for name in (
        "namespace.yaml",
        "configmap.yaml",
        "deployment.yaml",
        "service.yaml",
        "secret.example.yaml",
        "ingress.example.yaml",
        "networkpolicy.example.yaml",
    ):
        document = _load(name)
        assert document["kind"]
        assert document["apiVersion"]


def test_deployment_pins_the_image_tag():
    deployment = _load("deployment.yaml")
    image = _container(deployment)["image"]

    assert ":" in image
    assert not image.endswith(":latest"), f"must not use :latest, got {image!r}"
    assert image.endswith(f":{__version__}"), f"expected the {__version__} tag, got {image!r}"


def test_deployment_probes_target_the_right_endpoints():
    deployment = _load("deployment.yaml")
    container = _container(deployment)

    readiness = container["readinessProbe"]["httpGet"]
    liveness = container["livenessProbe"]["httpGet"]

    assert readiness["path"] == "/readyz"
    assert liveness["path"] == "/healthz"


def test_deployment_runs_as_non_root_and_read_only():
    deployment = _load("deployment.yaml")
    container = _container(deployment)
    container_security = container["securityContext"]
    pod_security = deployment["spec"]["template"]["spec"]["securityContext"]

    assert pod_security["runAsNonRoot"] is True
    assert pod_security["runAsUser"] == 10001
    assert container_security["readOnlyRootFilesystem"] is True
    assert container_security["allowPrivilegeEscalation"] is False


def test_deployment_has_two_replicas():
    deployment = _load("deployment.yaml")

    assert deployment["spec"]["replicas"] == 2


def test_deployment_reads_secrets_through_env_from():
    deployment = _load("deployment.yaml")
    container = _container(deployment)

    secret_refs = [
        item["secretRef"]["name"] for item in container.get("envFrom", []) if "secretRef" in item
    ]
    assert "keystone-secrets" in secret_refs

    # The Secret's own keys never appear as a literal env value in the Deployment.
    plain_env_names = {item["name"] for item in container.get("env", [])}
    assert "KEYSTONE_MCP_REDIS_URL" not in plain_env_names
    assert "KEYSTONE_MCP_USERS_DB_URL" not in plain_env_names
    assert "KEYSTONE_MCP_LOGIN_GOOGLE_SECRET" not in plain_env_names
    assert "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT" not in plain_env_names


def test_service_is_cluster_ip_on_8080():
    service = _load("service.yaml")

    assert service["spec"]["type"] == "ClusterIP"
    ports = service["spec"]["ports"]
    assert len(ports) == 1
    assert ports[0]["port"] == 8080


def test_secret_example_is_a_template_not_real_credentials():
    secret = _load("secret.example.yaml")
    string_data = secret["stringData"]

    expected_keys = {
        "KEYSTONE_MCP_LOGIN_GOOGLE_SECRET",
        "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT",
        "KEYSTONE_MCP_REDIS_URL",
        "KEYSTONE_MCP_USERS_DB_URL",
    }
    assert set(string_data) == expected_keys
    for key in ("KEYSTONE_MCP_LOGIN_GOOGLE_SECRET", "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"):
        assert "CHANGE_ME" in string_data[key]


def test_configmap_carries_both_policy_files():
    configmap = _load("configmap.yaml")
    data = configmap["data"]

    assert "rbac-policy.yaml" in data
    assert "upstreams.yaml" in data

    policy = yaml.safe_load(data["rbac-policy.yaml"])
    assert policy["roles"]["administrator"]["allow"] == ["*"]

    registry = yaml.safe_load(data["upstreams.yaml"])
    assert registry["entries"] == []


def test_ingress_example_sets_proxy_buffering_off():
    ingress = _load("ingress.example.yaml")
    annotations = ingress["metadata"]["annotations"]

    assert annotations["nginx.ingress.kubernetes.io/proxy-buffering"] == "off"


def test_networkpolicy_example_restricts_ingress_to_keystone_pods():
    """An upstream on a bare ClusterIP Service (configmap.yaml's advice) has
    no network-level protection against a forged ``X-Author-Email`` sent by
    any other pod in the cluster. This example locks an upstream's ingress
    down to pods carrying the Keystone Deployment's own label
    (``app: keystone``, same as ``deployment.yaml``'s pod template)."""
    policy = _load("networkpolicy.example.yaml")

    assert policy["kind"] == "NetworkPolicy"
    spec = policy["spec"]
    assert spec["policyTypes"] == ["Ingress"]

    deployment = _load("deployment.yaml")
    keystone_pod_labels = deployment["spec"]["template"]["metadata"]["labels"]

    peers = [peer for rule in spec["ingress"] for peer in rule.get("from", [])]
    assert peers, "the example must restrict ingress to at least one peer"
    assert any(
        peer.get("podSelector", {}).get("matchLabels") == keystone_pod_labels for peer in peers
    ), (
        "must select Keystone's own pods "
        f"({keystone_pod_labels!r}) as the only allowed ingress source"
    )


def test_docs_describe_the_upstream_impersonation_mitigations():
    text = (REPO_ROOT / "docs" / "paths" / "kubernetes.md").read_text(encoding="utf-8")

    assert "networkpolicy.example.yaml" in text
    assert "auth.bearer_env" in text
    assert "X-Author-Email" in text


def test_configmap_policy_equals_production_policy():
    configmap = _load("configmap.yaml")
    embedded = yaml.safe_load(configmap["data"]["rbac-policy.yaml"])
    production = yaml.safe_load(PRODUCTION_POLICY.read_text(encoding="utf-8"))
    assert embedded == production


def test_example_policies_cover_shipped_tool_dispositions():
    production = yaml.safe_load(PRODUCTION_POLICY.read_text(encoding="utf-8"))
    shipped = yaml.safe_load(SHIPPED_POLICY.read_text(encoding="utf-8"))
    assert production["version"] == shipped["version"]

    def _tool_names(dispositions: dict[str, list[str]]) -> set[str]:
        names: set[str] = set()
        for group in dispositions.values():
            names.update(group)
        return names

    assert _tool_names(production["tool_dispositions"]) >= _tool_names(shipped["tool_dispositions"])


def test_read_only_policy_mount_sets_policy_tools_read_only():
    deployment = _load("deployment.yaml")
    container = _container(deployment)
    env = {item["name"]: item["value"] for item in container.get("env", []) if "value" in item}
    assert env.get("KEYSTONE_MCP_POLICY_TOOLS") == "read-only"


def test_deployment_uses_login_providers_file():
    deployment = _load("deployment.yaml")
    container = _container(deployment)
    env = {item["name"]: item["value"] for item in container.get("env", []) if "value" in item}
    forbidden = {
        "KEYSTONE_MCP_ENABLED_LOGIN_METHODS",
        "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD",
        "KEYSTONE_MCP_GOOGLE_CLIENT_ID",
        "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET",
        "KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN",
    }
    assert forbidden.isdisjoint(env)
    assert env.get("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH") == "/etc/keystone-mcp/login-providers.yaml"

    configmap = _load("configmap.yaml")
    providers = yaml.safe_load(configmap["data"]["login-providers.yaml"])
    secret_env_names = {
        p["client_secret_env"] for p in providers["providers"] if p.get("client_secret_env")
    }
    secret = _load("secret.example.yaml")
    assert secret_env_names <= set(secret["stringData"])


def test_deployment_starts_without_deprecation_or_w7(monkeypatch, tmp_path: Path):
    deployment = _load("deployment.yaml")
    configmap = _load("configmap.yaml")
    secret = _load("secret.example.yaml")

    etc = tmp_path / "etc" / "keystone-mcp"
    etc.mkdir(parents=True)
    policy_path = etc / "rbac-policy.yaml"
    policy_path.write_text(configmap["data"]["rbac-policy.yaml"], encoding="utf-8")
    (etc / "upstreams.yaml").write_text(configmap["data"]["upstreams.yaml"], encoding="utf-8")
    (etc / "login-providers.yaml").write_text(
        configmap["data"]["login-providers.yaml"], encoding="utf-8"
    )
    os.chmod(policy_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    container = _container(deployment)
    plain_env = {
        item["name"]: item["value"] for item in container.get("env", []) if "value" in item
    }
    for key, value in secret["stringData"].items():
        if key == "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT":
            monkeypatch.setenv(key, "a" * 32)
        elif key == "KEYSTONE_MCP_REDIS_URL":
            monkeypatch.setenv(key, UNUSED_REDIS_URL)
        else:
            monkeypatch.setenv(key, value)
    for key, value in plain_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS_PATH", str(etc / "upstreams.yaml"))
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", str(etc / "login-providers.yaml"))

    if os.geteuid() == 0:
        pytest.skip("root can write a read-only policy file")

    settings = load_settings()
    warnings = startup_warnings(settings)
    combined = " ".join(warnings).lower()
    assert "deprecated" not in combined
    assert "not writable" not in combined


def test_deployment_has_graceful_shutdown_settings():
    deployment = _load("deployment.yaml")
    pod_spec = deployment["spec"]["template"]["spec"]
    container = _container(deployment)

    assert pod_spec.get("automountServiceAccountToken") is False
    grace = pod_spec.get("terminationGracePeriodSeconds", 0)
    pre_stop = container.get("lifecycle", {}).get("preStop", {})
    pre_stop_seconds = 5 if pre_stop.get("exec", {}).get("command") == ["sleep", "5"] else 0
    assert pre_stop_seconds == 5

    env = {item["name"]: item["value"] for item in container.get("env", []) if "value" in item}
    shutdown_grace = int(env.get("KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS", "0"))
    assert grace >= pre_stop_seconds + shutdown_grace + 5

    startup = container.get("startupProbe", {}).get("httpGet", {})
    assert startup.get("path") == "/healthz"
    probe = container["startupProbe"]
    assert probe["periodSeconds"] * probe["failureThreshold"] >= 180
    assert "initialDelaySeconds" not in container.get("livenessProbe", {})


def test_pdb_is_applied():
    pdb = _load("pdb.yaml")
    assert pdb["spec"]["minAvailable"] == 1
    assert pdb["spec"]["selector"]["matchLabels"] == {"app": "keystone"}


def test_ingress_uses_ingress_class_name():
    ingress = _load("ingress.example.yaml")
    assert ingress["spec"].get("ingressClassName") == "nginx"
    annotations = ingress["metadata"].get("annotations") or {}
    assert "kubernetes.io/ingress.class" not in annotations
