"""Offline-first Kubernetes manifest/CRD builder and optional cluster readiness helper."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from packages.core.config.settings import Settings, get_settings


def build_vulnerability_assessment_cr(
    *,
    name: str,
    target_path: str,
    namespace: str = "vexreach",
    workload_name: str = "default-workload",
    internet_facing: bool = False,
    criticality: str = "medium",
    enable_osv_enrichment: bool = False,
    enable_python_reachability: bool = True,
    enable_attack_paths: bool = True,
    emit_openvex: bool = True,
) -> dict[str, Any]:
    """Build a structured VulnerabilityAssessment CRD custom resource offline."""
    return {
        "apiVersion": "vexreach.security.io/v1alpha1",
        "kind": "VulnerabilityAssessment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "vexreach",
                "app.kubernetes.io/managed-by": "vexreach-backend",
            },
        },
        "spec": {
            "targetPath": target_path,
            "workloadName": workload_name,
            "internetFacing": internet_facing,
            "criticality": criticality,
            "enableOsvEnrichment": enable_osv_enrichment,
            "enablePythonReachability": enable_python_reachability,
            "enableAttackPaths": enable_attack_paths,
            "emitOpenVex": emit_openvex,
            "suspend": False,
        },
    }


def build_assessment_job_manifest(
    *,
    name: str,
    target_path: str,
    namespace: str = "vexreach",
    image: str = "ghcr.io/adityasystems99/vexreach:latest",
    emit_vex: bool = True,
    compute_risk: bool = True,
) -> dict[str, Any]:
    """Generate a least-privilege non-root Kubernetes batch/v1 Job manifest."""
    args = ["scan", target_path, "--output-dir", "/var/lib/vexreach/assessments"]
    if emit_vex:
        args.append("--emit-vex")
    if compute_risk:
        args.append("--risk")

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": "vexreach-worker"},
        },
        "spec": {
            "backoffLimit": 1,
            "ttlSecondsAfterFinished": 3600,
            "template": {
                "spec": {
                    "serviceAccountName": "vexreach-worker",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "vexreach",
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["python", "-m", "apps.cli.main"],
                            "args": args,
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "resources": {
                                "requests": {"cpu": "250m", "memory": "256Mi"},
                                "limits": {"cpu": "1000m", "memory": "1Gi"},
                            },
                        }
                    ],
                }
            },
        },
    }


def inspect_kubernetes_environment(settings: Settings | None = None) -> dict[str, Any]:
    """Inspect local kubeconfig / in-cluster environment safely without connecting to API server."""
    cfg = settings or get_settings()
    in_cluster_token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").is_file()
    kubeconfig_candidate = (
        Path(cfg.kubeconfig_path)
        if cfg.kubeconfig_path
        else Path(os.environ.get("KUBECONFIG", Path.home() / ".kube" / "config"))
    )
    kubeconfig_present = kubeconfig_candidate.is_file()
    return {
        "kubernetes_enabled": cfg.kubernetes_enabled,
        "namespace": cfg.kubernetes_namespace,
        "in_cluster_service_account": in_cluster_token,
        "kubeconfig_present": kubeconfig_present,
        "kubeconfig_path": str(kubeconfig_candidate) if kubeconfig_present else None,
        "mode": (
            "cluster_configured"
            if cfg.kubernetes_enabled and (in_cluster_token or kubeconfig_present)
            else "offline_manifest_mode"
        ),
    }
