# DAY 8 — LIVE KUBERNETES DEPLOYMENT & CNI NETWORKPOLICY REPORT

**Date:** 2026-11-28  
**Engineer:** Principal Systems, Kubernetes & DevSecOps Engineer  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Previous Security Baseline:** `41280d75644ff42726de3172a751eede0927f798` (Day 7 Audit)  
**Classification:** Unaudited Research Prototype — Live Local `kind` + Calico Cluster Verification  

---

## 1. Executive Summary

Private Relay v0.1 was deployed cleanly onto a live local Kubernetes cluster (`kind` `v0.27.0`, Kubernetes `v1.32.2`) configured with **Calico CNI `v3.29.1`** (`disableDefaultCNI: true`) so both Pod workloads and L3/L4 `NetworkPolicy` drops execute against real kernel networking rather than offline YAML rendering.

All **6 Deployments** (`private-relay-entry`, `private-relay-middle`, `private-relay-exit`, `private-relay-destination`, `prometheus`, `grafana`) reached `READY 1/1` (`0` restarts after rollout), both **Jobs** (`private-relay-keygen`, `private-relay-client`) completed cleanly, all **12 multi-hop traffic scenarios** (`Client -> Entry -> Middle -> Exit -> Destination`) passed inside the cluster, and **15/15 live Calico `NetworkPolicy` enforcement checks** matched the exact hop-locked topology.

---

## 2. Cluster Identity, Runtime & CNI Architecture

| Component | Verified Value | Evidence / Method |
|---|---|---|
| **Docker Engine** | `29.5.3` (16 CPUs, `15.26 GiB` RAM, WSL2 backend) | Started cleanly via `docker desktop start --timeout 180` |
| **Cluster Provisioner** | `kind` `v0.27.0` (`go1.23.6`, cluster name `private-relay`) | `kind create cluster --name private-relay` (`disableDefaultCNI: true`, `podSubnet: 192.168.0.0/16`) |
| **Kubernetes Control Plane** | Server `v1.32.2` (`private-relay-control-plane`), `kubectl` `v1.34.1`, `Kustomize` `v5.7.1` | `kubectl version` / `kubectl get nodes -o wide` |
| **Container Runtime / Kernel** | `containerd://2.0.2`, Debian 12 (`bookworm`), Linux `6.18.58.1-microsoft-standard-WSL2` | `kubectl get nodes -o wide` |
| **CNI Plugin** | **Calico `v3.29.1`** (`calico-node` + `calico-kube-controllers`, `FELIX_IGNORELOOSERPF=true`) | Real `NetworkPolicy` L3/L4 enforcement verified across Pods |
| **Application Image** | `private-relay:v0.1` (`32.8 MB` stripped Rust runtime) + `alpine/kubectl:1.34.1`, `prom/prometheus:v2.53.0`, `grafana/grafana:11.1.0` | Verified inside `private-relay-control-plane` via `crictl images` |

---

## 3. Deployed Workloads & Manifest Findings (`kubectl apply -k k8s/`)

Total rendered and applied objects: **39 Kubernetes resources** (`namespace/private-relay` enforcing `Pod Security Standards: restricted`):
- **Jobs (2):** `private-relay-keygen` (`Complete 1/1`, `23s`), `private-relay-client` (`Complete 1/1` after initial backoff waiting for keygen + rollout).
- **Deployments (6 — all `1/1 Available`):** `private-relay-destination`, `private-relay-exit`, `private-relay-middle`, `private-relay-entry`, `prometheus`, `grafana`.
- **ClusterIP Services (9):** Application services (`entry:9101`, `middle:9102`, `exit:9103`, `destination:9000`), dedicated metrics services (`entry-metrics:9091`, `middle-metrics:9091`, `exit-metrics:9091`), and monitoring services (`prometheus:9090`, `grafana:3000`).
- **ConfigMaps (8) & Secrets (3):** Per-node ConfigMaps without keys (`private-relay-entry-config`, `middle-config`, `exit-config`, `client-config`, plus Prometheus/Grafana configs) and isolated per-node Secrets (`private-relay-entry-secret`, `middle-secret`, `exit-secret`).
- **NetworkPolicies (10):** `default-deny-all`, `allow-dns-egress`, `allow-client-egress-to-entry`, `entry-relay-policy`, `middle-relay-policy`, `exit-relay-policy`, `destination-policy`, `keygen-policy`, `prometheus-policy`, `grafana-policy`.

### Manifest Defects Found & Fixed During Day 8
1. **`configmaps.yaml` field name mismatch:** Static skeleton used `max_circuits_per_ip = 32` instead of `RelayConfig`'s `max_circuits_per_peer_ip = 32`; fixed to match struct schema.
2. **Metrics exposure & Service naming mismatch:** Added `--metrics-addr 0.0.0.0:9091` and container port `9091` (`metrics`) to `entry`, `middle`, and `exit` Deployments, added dedicated `*-metrics` ClusterIP Services, and updated `NetworkPolicy` so **only** `prometheus` pods can scrape TCP `9091` while client pods are denied.
3. **Observability PSS `restricted` compliance:** Added `automountServiceAccountToken: false`, `readOnlyRootFilesystem: true`, `emptyDir` mounts for `/prometheus` TSDB, Grafana `/var/lib/grafana` + `/tmp` (moving provisioned dashboards to `/etc/grafana/dashboards` to prevent volume shadowing), and HTTP readiness/liveness probes (`/-/ready`, `/api/health`).
4. **Initial Client Job startup retries:** Because `kubectl apply -k k8s/` applies `keygen-job` and `client-job` concurrently, `client-job` cleanly experienced `3` backoff restarts (`<35s`) until `keygen-job` and relay rollout completed, then succeeded on attempt 4 (`elapsed_ms: 36`).

---

## 4. Secrets, Identity & Security Context Verification (`Section 8.3`)

- **Keygen Execution:** `private-relay-keygen` initContainer printed `KEYGEN_OK out_dir=/work`; `publish-k8s-objects` created all ConfigMaps and per-node Secrets without printing key hex to logs.
- **Zero Secrets in ConfigMaps / Env / Client:**
  - Verified all ConfigMaps in `private-relay` contain zero `private_key_hex =` fields (`private_key_file = "/run/secrets/private_key_hex"` only).
  - Verified `private-relay-client-config` contains strictly `entry`/`middle`/`exit` `public_key_hex` descriptors.
  - Verified inside live `entry`, `middle`, `exit`, and `test-client` Pods via `kubectl exec`:
    - Processes run strictly as `uid=10001(relay) gid=10001(relay)`.
    - `/cfg` and `/run/secrets` mount via kubelet atomic `..data` symlinks (`subPath` eliminated).
    - Zero `private_key` entries appear in container `env` or container logs.
    - `/run/secrets` does not exist inside the `client` Pod.

---

## 5. Live Multi-Hop Traffic Verification (`Section 8.4`)

Executed inside PSS-restricted `pod/private-relay-test-client` across `Client -> Entry -> Middle -> Exit -> Destination`:

| # | Scenario | Result | Observed Output Summary |
|---|---|---|---|
| 1 | Empty raw request (`0B`) | **VERIFIED** | `connection: OK`, `response_bytes: 0`, `elapsed_ms: 31` |
| 2 | HTTP health check (`/health`) | **VERIFIED** | `outcome: OK (http_status="HTTP/1.1 200 OK")`, `response_bytes: 142`, `elapsed_ms: 17` |
| 3 | Medium HTTP payload (`/medium`, 12 KiB) | **VERIFIED** | `outcome: OK (http_status="HTTP/1.1 200 OK")`, `response_bytes: 12375`, `elapsed_ms: 61` |
| 4 | Max `64 KiB` raw request (`65536B`) | **VERIFIED** | `transmission: OK (request_bytes=65536)`, `response_bytes: 65536`, `elapsed_ms: 130` |
| 5 | Max `64 KiB` HTTP response (`/max-64kib`) | **VERIFIED** | `outcome: OK (http_status="HTTP/1.1 200 OK")`, `response_bytes: 65536`, `elapsed_ms: 72` |
| 6 | Redirect non-follow (`/redirect-ssrf`) | **VERIFIED** | `outcome: OK (http_status="HTTP/1.1 302 Found")`, `response_bytes: 112`, `elapsed_ms: 16` |
| 7 | Oversized request (`65537B`) | **VERIFIED** | `REJECTED_LOCALLY` (`exceeds maximum 65536 bytes`, exit `1`, `elapsed_ms: 10`) |
| 8 | Private IP SSRF denial (`10.0.0.1:80`) | **VERIFIED** | `REMOTE_ERROR(PolicyDenied: destination blocked by exit SSRF policy)`, `elapsed_ms: 12` |
| 9 | Loopback SSRF denial (`127.0.0.1:9000`) | **VERIFIED** | `REMOTE_ERROR(PolicyDenied: destination blocked by exit SSRF policy)`, `elapsed_ms: 11` |
| 10 | Metadata IP SSRF denial (`169.254.169.254:80`) | **VERIFIED** | `REMOTE_ERROR(PolicyDenied: destination blocked by exit SSRF policy)`, `elapsed_ms: 10` |
| 11 | Oversized destination response (`/oversized`) | **VERIFIED** | `REMOTE_ERROR(PayloadTooLarge: payload exceeded 64 KiB bound)`, `elapsed_ms: 16` |
| 12 | Slow destination timeout (`/slow`) | **VERIFIED** | `REMOTE_ERROR(Timeout: destination I/O timed out)`, `elapsed_ms: 5012` |

---

## 6. Live Calico `NetworkPolicy` Enforcement Verification (`Section 8.5`)

Probed live between Pods using `/usr/local/bin/relay-client --probe <HOST:PORT>` (`2s` connect timeout):

| Source Workload | Target Service / Address | Expected | Actual Calico Result |
|---|---|---|---|
| `pod/private-relay-test-client` | `private-relay-entry:9101` | ALLOWED | **ALLOWED** |
| `pod/private-relay-test-client` | `private-relay-middle:9102` | DENIED | **DENIED** |
| `pod/private-relay-test-client` | `private-relay-exit:9103` | DENIED | **DENIED** |
| `pod/private-relay-test-client` | `private-relay-destination:9000` | DENIED | **DENIED** |
| `pod/private-relay-test-client` | `private-relay-entry-metrics:9091` | DENIED | **DENIED** |
| `pod/private-relay-test-client` | `1.1.1.1:80` (External Internet Egress) | DENIED | **DENIED** |
| `deployment/private-relay-entry` | `private-relay-middle:9102` | ALLOWED | **ALLOWED** |
| `deployment/private-relay-entry` | `private-relay-exit:9103` | DENIED | **DENIED** |
| `deployment/private-relay-entry` | `private-relay-destination:9000` | DENIED | **DENIED** |
| `deployment/private-relay-middle` | `private-relay-exit:9103` | ALLOWED | **ALLOWED** |
| `deployment/private-relay-middle` | `private-relay-destination:9000` | DENIED | **DENIED** |
| `deployment/private-relay-middle` | `private-relay-entry:9101` | DENIED | **DENIED** |
| `deployment/private-relay-exit` | `private-relay-destination:9000` | ALLOWED | **ALLOWED** |
| `deployment/private-relay-exit` | `private-relay-entry:9101` | DENIED | **DENIED** |
| `deployment/private-relay-destination` | `private-relay-entry:9101` | DENIED | **DENIED** |

Prometheus -> `private-relay-{entry,middle,exit}-metrics:9091` scraping and Grafana -> `prometheus:9090` queries also succeeded through Calico policies (documented in Day 10).

---

## 7. Known Limitations (`v0.1`)

- Relays remain single-replica (`replicas: 1`, `strategy: Recreate`) because static X25519 keys and `CircuitTable` state reside in local Pod RAM (`KI-10`).
- Local cluster verification proves single-node `kind` + Calico enforcement; multi-node bare-metal/cloud production KMS/Vault secret injection and Coordinator discovery remain post-`v0.1`.
- Private Relay remains an **unaudited research prototype** and does not protect against dual-ended global traffic correlation (`KI-01`).
