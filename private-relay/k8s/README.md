# Private-Relay Kubernetes Deployment (`k8s/`)

Kustomize-managed Kubernetes manifests deploying the verified Private-Relay v0.1 architecture (`Client -> Entry -> Middle -> Exit -> Destination`) plus privacy-preserving observability (`Prometheus` + `Grafana`) under strict **Pod Security Standards (`restricted`)**, per-node Secret separation, Calico-verified `NetworkPolicy` isolation, and cryptographic/HTTP readiness probes.

> **Verification Status Note (Days 8–10):**
> Verified live on **`kind` `v0.27.0` (Kubernetes `v1.32.2`)** with **Calico CNI `v3.29.1`**: all 6 Deployments (`destination`, `exit`, `middle`, `entry`, `prometheus`, `grafana`) `READY 1/1`, both Jobs (`keygen`, `client`) `Completed`, **12/12** live in-cluster multi-hop traffic cases, **15/15** live Calico `NetworkPolicy` allow/deny probes, live Pod restart/fail-closed/mid-flight `SIGTERM` resilience tests, live Prometheus scraping (`sum(private_relay_up) = 3`), and Grafana 10-panel dashboard verification (see [DAY_8_DEPLOYMENT_REPORT.md](../docs/DAY_8_DEPLOYMENT_REPORT.md), [DAY_9_RESILIENCE_REPORT.md](../docs/DAY_9_RESILIENCE_REPORT.md), [DAY_10_OBSERVABILITY_REPORT.md](../docs/DAY_10_OBSERVABILITY_REPORT.md)).

---

## Architecture & Isolation

| Component | Manifests | Port(s) | Secret Mount | Probe Method |
| --- | --- | --- | --- | --- |
| `destination` | `destination-deployment.yaml`, `destination-service.yaml` | `9000/TCP` | None | `relay-client --probe-http 127.0.0.1:9000` (`GET /health` HTTP 200 JSON) |
| `exit` | `exit-deployment.yaml`, `exit-service.yaml` | `9103/TCP`, `9091/TCP` (`metrics`) | `private-relay-exit-secret` -> `/run/secrets/private_key_hex` | `relay-client --probe-noise 127.0.0.1:9103 --pubkey-toml /cfg/exit.toml` |
| `middle` | `middle-deployment.yaml`, `middle-service.yaml` | `9102/TCP`, `9091/TCP` (`metrics`) | `private-relay-middle-secret` -> `/run/secrets/private_key_hex` | `relay-client --probe-noise 127.0.0.1:9102 --pubkey-toml /cfg/middle.toml` |
| `entry` | `entry-deployment.yaml`, `entry-service.yaml` | `9101/TCP`, `9091/TCP` (`metrics`) | `private-relay-entry-secret` -> `/run/secrets/private_key_hex` | `relay-client --probe-noise 127.0.0.1:9101 --pubkey-toml /cfg/entry.toml` |
| `client` | `client-job.yaml` | None | None | Runs one-shot E2E HTTP onion request to `destination:9000/health` |
| `keygen` | `keygen-job.yaml` | None | Writes initial ConfigMaps & per-node Secrets | Ephemeral `Job` using namespace-scoped `Role` |
| `prometheus` | `observability-prometheus.yaml` | `9090/TCP` | None | HTTP `/-/ready`, scrapes `private-relay-*-metrics:9091/metrics` |
| `grafana` | `observability-grafana.yaml` | `3000/TCP` | None | HTTP `/api/health`, queries `prometheus:9090`, loads 10-panel dashboard |

### Hardening Guarantees
- **PSS `restricted` Namespace:** `runAsNonRoot: true`, `runAsUser: 10001` (relays/dest/client) / `65534` (Prometheus) / `472` (Grafana), `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`.
- **Zero Secrets in Git:** `secrets.example.yaml` is intentionally excluded from `kustomization.yaml`. Relays refuse to start until unique per-deployment X25519 keys are provisioned.
- **No Secret Env Vars & Zero `subPath`:** Private keys are mounted via whole-directory `Secret` volumes (`/run/secrets/private_key_hex`, mode `0440` with `fsGroup: 10001`) enabling atomic rotation and zeroed in relay RAM upon keypair parsing.
- **Hop-Locked `NetworkPolicy` (10 policies):** `default-deny-all` + strict egress/ingress allowing ONLY `Client -> Entry(9101) -> Middle(9102) -> Exit(9103) -> Dest(9000)`, `Prometheus -> Entry/Middle/Exit(9091)`, and `Grafana -> Prometheus(9090)`. Verified under **Calico `v3.29.1`**.
- **Single-Replica Constraint (`v0.1`):** Each relay Deployment keeps `replicas: 1` (`strategy.type: Recreate`) because `v0.1` relays hold unique pinned X25519 keys and ephemeral RAM-only `CircuitTable` state.

---

## Prerequisites

1. A running Kubernetes cluster with a `NetworkPolicy`-enforcing CNI (tested on `kind v0.27.0` with `disableDefaultCNI: true` + `Calico v3.29.1`). *(Default `kindnet` accepts `NetworkPolicy` manifests without enforcing packet drops.)*
2. Local container image `private-relay:v0.1` built from `private-relay/Dockerfile`:
   ```powershell
   docker compose build
   ```
3. Make the image available inside your cluster nodes (`kind load docker-image private-relay:v0.1 --name private-relay`). Note that on Docker Desktop with containerd snapshotter enabled, multi-arch Docker Hub helper images (`alpine/kubectl:1.34.1`, `prom/prometheus:v2.53.0`, `grafana/grafana:11.1.0`) can be pre-pulled directly in the node via `crictl pull` if not pulled automatically.

---

## Quick Start (PowerShell)

### 1. Deploy Manifests & Provision Cryptographic Identities
```powershell
kubectl apply -k k8s/
kubectl wait -n private-relay --for=condition=complete job/private-relay-keygen --timeout=120s
```

### 2. Restart Relays to Pick Up Final Keygen Secrets, Then Wait for Readiness
```powershell
kubectl rollout restart -n private-relay deployment/private-relay-exit deployment/private-relay-middle deployment/private-relay-entry
kubectl wait -n private-relay --for=condition=available deployment --all --timeout=180s
```

### 3. Verify Three-Hop Circuit Execution
```powershell
kubectl wait -n private-relay --for=condition=complete job/private-relay-client --timeout=180s
kubectl logs -n private-relay job/private-relay-client
```

### 4. Access Prometheus & Grafana Locally
```powershell
kubectl port-forward -n private-relay svc/prometheus 19090:9090
kubectl port-forward -n private-relay svc/grafana 13000:3000
# Grafana credentials: admin / private-relay-local
```

### 5. Cleanup
```powershell
kubectl delete -k k8s/
```
