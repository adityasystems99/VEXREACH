# VEXReach Container & Kubernetes Deployment Guide

VEXReach is a **backend-first platform** supporting offline local CLI execution, Dockerized REST API hosting, and Kubernetes-native worker job execution without assuming live cluster access.

---

## 1. Docker & Docker Compose (Backend Only)

Build and launch the non-root backend REST API (`port 8000`) cleanly:

```bash
cp .env.example .env
# Edit .env and configure VEXREACH_API_KEYS before enabling VEXREACH_API_AUTH_ENABLED=true
docker compose -f deploy/docker/docker-compose.yml up --build vexreach-api
```

Security controls applied in `deploy/docker/Dockerfile` and `docker-compose.yml`:
- Runs as non-root system user `vexreach` (`UID/GID 10001`).
- `read_only: true` root filesystem with dedicated `/tmp` (`noexec,nosuid`) and `/var/lib/vexreach` volume.
- `cap_drop: [ALL]` and `no-new-privileges: true`.

---

## 2. Kubernetes Manifests (Namespace-Scoped Least Privilege)

All Kubernetes resources live under [`deploy/kubernetes/`](../../deploy/kubernetes/):
1. `crd-vulnerabilityassessment.yaml` — Registers `VulnerabilityAssessment` (`vxa`) CRD (`vexreach.security.io/v1alpha1`).
2. `serviceaccount-rbac.yaml` — Creates `vexreach-worker` ServiceAccount (`automountServiceAccountToken: false`) and a strictly namespace-scoped `Role`/`RoleBinding` (**no ClusterRole / no cluster-admin**).
3. `configmap-example.yaml` & `secret-example.yaml` — Runtime settings (`secret-example.yaml` contains placeholder values only; inject real keys via External Secrets / Vault in production).
4. `job-assessment-worker.yaml` — Bounded non-root `batch/v1` Job executing `python -m apps.cli.main scan ... --emit-vex --risk`.

Dry-run offline generation is built into `packages/core/integrations/kubernetes.py` (`build_vulnerability_assessment_cr`, `build_assessment_job_manifest`, `inspect_kubernetes_environment`).

---

## 3. Helm Chart

A parameterized chart lives under [`deploy/helm/vexreach/`](../../deploy/helm/vexreach/) deploying the REST API (`Deployment` + `Service`), liveness/readiness probes (`/healthz`, `/readyz`), and namespace-scoped RBAC.
