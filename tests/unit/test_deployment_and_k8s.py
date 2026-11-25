"""Unit tests verifying offline Kubernetes manifest builders, Helm/RBAC least-privilege guards, and Docker backend config."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.core.config.settings import Settings
from packages.core.integrations.kubernetes import (
    build_assessment_job_manifest,
    build_vulnerability_assessment_cr,
    inspect_kubernetes_environment,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_offline_kubernetes_cr_and_job_manifest_builders() -> None:
    cr = build_vulnerability_assessment_cr(
        name="sample-repo-scan",
        target_path="/workspace/sample",
        namespace="vexreach",
        workload_name="payments-api",
        internet_facing=True,
        criticality="critical",
    )
    assert cr["apiVersion"] == "vexreach.security.io/v1alpha1"
    assert cr["kind"] == "VulnerabilityAssessment"
    assert cr["spec"]["targetPath"] == "/workspace/sample"
    assert cr["spec"]["internetFacing"] is True

    job = build_assessment_job_manifest(
        name="vxa-sample-repo-scan",
        target_path="/workspace/sample",
        namespace="vexreach",
    )
    assert job["kind"] == "Job"
    pod_spec = job["spec"]["template"]["spec"]
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    assert pod_spec["securityContext"]["runAsUser"] == 10001
    c_sec = pod_spec["containers"][0]["securityContext"]
    assert c_sec["allowPrivilegeEscalation"] is False
    assert c_sec["readOnlyRootFilesystem"] is True
    assert c_sec["capabilities"]["drop"] == ["ALL"]


@pytest.mark.unit
def test_inspect_kubernetes_environment_works_without_cluster(tmp_path: Path) -> None:
    settings = Settings(
        kubernetes_enabled=False,
        kubeconfig_path=str(tmp_path / "nonexistent-kubeconfig"),
    )
    info = inspect_kubernetes_environment(settings)
    assert info["kubernetes_enabled"] is False
    assert info["mode"] == "offline_manifest_mode"
    assert info["kubeconfig_present"] is False


@pytest.mark.unit
def test_k8s_rbac_docker_and_helm_manifests_enforce_least_privilege() -> None:
    import yaml

    rbac_docs = list(
        yaml.safe_load_all(
            (REPO_ROOT / "deploy" / "kubernetes" / "serviceaccount-rbac.yaml").read_text(
                encoding="utf-8"
            )
        )
    )
    kinds = {d["kind"] for d in rbac_docs if isinstance(d, dict)}
    assert kinds == {"ServiceAccount", "Role", "RoleBinding"}
    assert not any(
        d.get("roleRef", {}).get("name") == "cluster-admin"
        for d in rbac_docs
        if isinstance(d, dict)
    )
    sa_doc = next(d for d in rbac_docs if d["kind"] == "ServiceAccount")
    assert sa_doc["automountServiceAccountToken"] is False

    secret_tpl = (REPO_ROOT / "deploy" / "kubernetes" / "secret-example.yaml").read_text(
        encoding="utf-8"
    )
    assert "REPLACE_WITH_" in secret_tpl

    dockerfile = (REPO_ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001:10001" in dockerfile
    assert "apps.api.main:app" in dockerfile
    assert "vexreach-go-analyze" in dockerfile

    import json

    contract = json.loads((REPO_ROOT / "contracts" / "analysis_contract.json").read_text(encoding="utf-8"))
    assert "StaticReachabilityReport" in contract.get("schemas", {})

    chart_yaml = (REPO_ROOT / "deploy" / "helm" / "vexreach" / "Chart.yaml").read_text(
        encoding="utf-8"
    )
    assert "name: vexreach" in chart_yaml
    assert (REPO_ROOT / "operators" / "vexreach-operator" / "go.mod").is_file()

    for manifest_rel in (
        "deploy/kubernetes/crd-vulnerabilityassessment.yaml",
        "deploy/kubernetes/serviceaccount-rbac.yaml",
        "deploy/kubernetes/job-assessment-worker.yaml",
        "deploy/kubernetes/configmap-example.yaml",
        "deploy/kubernetes/secret-example.yaml",
        "deploy/docker/docker-compose.yml",
        "deploy/helm/vexreach/Chart.yaml",
        "deploy/helm/vexreach/values.yaml",
    ):
        docs = list(yaml.safe_load_all((REPO_ROOT / manifest_rel).read_text(encoding="utf-8")))
        assert docs and all(d is not None for d in docs), f"Invalid YAML in {manifest_rel}"
