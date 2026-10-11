"""Static checks on the Kubernetes example manifests.

No cluster, no ``kubectl``: these tests only parse YAML with
``yaml.safe_load`` (or ``safe_load_all`` for the multi-document ConfigMap
payload) and check the handful of properties that would otherwise silently
drift -- the pinned image tag, which probe checks which endpoint, the
non-root/read-only security posture, and which files kustomization.yaml
actually applies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
K8S_DIR = REPO_ROOT / "examples" / "kubernetes"


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
    assert resources == {"namespace.yaml", "configmap.yaml", "deployment.yaml", "service.yaml"}
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
    assert image.endswith(":0.4.0"), f"expected the 0.4.0 tag, got {image!r}"


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
    assert "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET" not in plain_env_names
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
        "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET",
        "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT",
        "KEYSTONE_MCP_REDIS_URL",
        "KEYSTONE_MCP_USERS_DB_URL",
    }
    assert set(string_data) == expected_keys
    for key in ("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"):
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
