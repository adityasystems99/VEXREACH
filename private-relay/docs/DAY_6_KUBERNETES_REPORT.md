# Day 6 Kubernetes Orchestration & Distributed Deployment Report — Private-Relay (`v0.1`)

> **Date:** `2026-11-27`  
> **Starting Verified Baseline:** `441ffe221d1d153884be9abd44bfb30d63a9e34f` (`Day 5` `master` / `origin/master`)  
> **Overall Status:** **PARTIAL (Manifests, Rust Probes, Secret Separation & Container Image VERIFIED; Live Cluster Deployment, E2E Traffic, Pod Resilience & Runtime NetworkPolicy Enforcement `NOT VERIFIED`)**  
> **Scope Guardrail:** All changes remain strictly inside `private-relay/`. Cryptographic invariants (`Noise_IK`, `Noise_NK`, `HKDF-SHA256`, `ChaCha20-Poly1305`, `600B` fixed frames, `D-01`–`D-09`) and Exit SSRF protections (`D4-01`, loopback blocked) remain unchanged. No host configuration was modified and no external Kubernetes distributions, Prometheus, Grafana, or LLM tools were installed.

---

## 1. Local Kubernetes Environment & Live Cluster Blocker

| Check | Command | Observed Output | Status |
| :--- | :--- | :--- | :--- |
| `kubectl` Client & Kustomize | `kubectl version --client` | `Client Version: v1.34.1`, `Kustomize Version: v5.7.1` | **Available** |
| Kubeconfig & Contexts | `kubectl config get-contexts` / `$env:USERPROFILE\.kube\config` | Empty contexts list; `KUBECONFIG_EXISTS=False` | **Absent** |
| Cluster Connectivity | `kubectl cluster-info` / `kubectl get nodes` | `error: couldn't get current server API group list: the server has asked for the client to provide credentials` | **No Cluster Running** |
| Local K8s Distributions | Search for `kind`, `minikube`, `k3d`, `helm` | None installed on `PATH` | **Absent** |
| Docker Desktop K8s Setting | Inspect `%APPDATA%\Docker\settings-store.json` | Kubernetes feature disabled | **Disabled on Host** |

Per Day 6 safety guardrails (*"Do not silently install unrelated software or change host configuration"*), Docker Desktop host settings were **not** altered and no local cluster binary (`kind`/`minikube`/`k3d`) was installed. All offline manifest generation, Rust cryptographic probe/secret-file enhancements, container image rebuilds, and offline Kustomize validation were executed and verified, while live cluster execution stages remain explicitly marked **`NOT VERIFIED`**.

---

## 2. Kubernetes Architecture & Manifest Inventory ([`k8s/`](../k8s/README.md))

Traffic preserves the exact verified five-component hop path via Kubernetes ClusterIP DNS:

```text
private-relay-client (Job)
  ──[9101 TCP / Noise_IK + 3-layer Onion]──▶ private-relay-entry (Deployment, 1 replica)
  ──[9102 TCP / Noise_IK + 2-layer Onion]──▶ private-relay-middle (Deployment, 1 replica)
  ──[9103 TCP / Noise_IK + 1-layer Onion]──▶ private-relay-exit (Deployment, 1 replica)
  ──[9000 TCP / HTTP or Raw TCP]──────────▶ private-relay-destination (Deployment, 1 replica)
```

| Manifest File | Kind(s) | Purpose & Security Highlights |
| :--- | :--- | :--- |
| [k8s/namespace.yaml](../k8s/namespace.yaml) | `Namespace` (`private-relay`) | Enforces Pod Security Standards (`pod-security.kubernetes.io/enforce: restricted`, `audit: restricted`, `warn: restricted`). |
| [k8s/configmaps.yaml](../k8s/configmaps.yaml) | `ConfigMap` (`4` objects) | Non-sensitive TOML skeletons (`private_key_file = "/run/secrets/private_key_hex"`, zero inline private keys). |
| [k8s/secrets.example.yaml](../k8s/secrets.example.yaml) | `Secret` (`3` examples) | Excluded from `kustomization.yaml`; documents required per-node Secret shape without committing keys. |
| [k8s/keygen-job.yaml](../k8s/keygen-job.yaml) | `ServiceAccount`, `Role`, `RoleBinding`, `Job` | Least-privilege namespace-scoped RBAC (`private-relay-keygen`); initContainer runs `relay-keygen --split-dirs --key-file-path /run/secrets/private_key_hex`; publishes ConfigMaps + isolated per-node Secrets cleanly without host-side key persistence. |
| [k8s/destination-deployment.yaml](../k8s/destination-deployment.yaml), [destination-service.yaml](../k8s/destination-service.yaml) | `Deployment`, `Service` | Runs `/usr/local/bin/demo-dest --listen 0.0.0.0:9000` (`ClusterIP:9000`, zero Secrets/ConfigMaps, `readinessProbe` `--probe-http`). |
| [k8s/exit-deployment.yaml](../k8s/exit-deployment.yaml), [exit-service.yaml](../k8s/exit-service.yaml) | `Deployment`, `Service` | Single-replica Exit (`9103/TCP`), mounts `exit-config` + ONLY `private-relay-exit-secret`, `readinessProbe` `--probe-noise`. |
| [k8s/middle-deployment.yaml](../k8s/middle-deployment.yaml), [middle-service.yaml](../k8s/middle-service.yaml) | `Deployment`, `Service` | Single-replica Middle (`9102/TCP`), mounts `middle-config` + ONLY `private-relay-middle-secret`, `readinessProbe` `--probe-noise`. |
| [k8s/entry-deployment.yaml](../k8s/entry-deployment.yaml), [entry-service.yaml](../k8s/entry-service.yaml) | `Deployment`, `Service` | Single-replica Entry (`9101/TCP`), mounts `entry-config` + ONLY `private-relay-entry-secret`, `readinessProbe` `--probe-noise`. |
| [k8s/client-job.yaml](../k8s/client-job.yaml) | `Job` (`backoffLimit: 12`) | One-shot Client (`--url http://private-relay-destination.private-relay.svc.cluster.local:9000/health --print-body`), mounts zero Secrets. |
| [k8s/network-policy.yaml](../k8s/network-policy.yaml) | `NetworkPolicy` (`8` objects) | Default-deny + strict hop-by-hop L3/L4 allowlist + targeted DNS (`kube-dns` TCP/UDP `53`). |
| [k8s/kustomization.yaml](../k8s/kustomization.yaml) | `Kustomization` | Composes all `26` rendered YAML documents across namespace `private-relay`. |

---

## 3. Secret Separation & PSS `restricted` Compliance

To satisfy Kubernetes least privilege without leaking cryptographic keys via environment variables or ConfigMaps:
1. Added optional `private_key_file` support to `RelayConfig` ([crates/network/src/config.rs](../crates/network/src/config.rs)), with `skip_serializing_if = "String::is_empty"` on `private_key_hex` so separated TOML ConfigMaps completely omit `private_key_hex`. Ambiguous configs specifying both inline key and file fail closed (`NetworkError::Config`). No environment-variable key fallback was added.
2. Added `--key-file-path <PATH|auto>` to `relay-keygen` ([crates/cli/src/lib.rs](../crates/cli/src/lib.rs)) so key generation emits non-sensitive node TOMLs alongside isolated `0600` (Unix) key files (`entry.key`, `middle.key`, `exit.key`).
3. Every Pod and Job in `k8s/` sets:
   - Pod `securityContext`: `runAsNonRoot: true`, `runAsUser: 10001`, `runAsGroup: 10001`, `fsGroup: 10001`, `seccompProfile.type: RuntimeDefault`.
   - Container `securityContext`: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`.
   - `automountServiceAccountToken: false` on all workload Pods/Jobs (only `keygen-job` mounts the namespace-scoped `private-relay-keygen` ServiceAccount).
   - Secret volumes use `defaultMode: 0440` (`288` decimal) paired with `fsGroup: 10001` so non-root UID `10001` can read `/run/secrets/private_key_hex` cleanly without world-readability.
4. **Production KMS Caveat:** While `keygen-job` avoids committed static keys for local clusters, production clusters MUST inject per-node keys via External Secrets Operator, Vault Agent Injector, or SealedSecrets backed by KMS/HSM instead of in-cluster bootstrap Jobs, and set `allow_private_targets_for_test = false` unless Exit intentionally targets cluster-internal destinations.

---

## 4. Real Readiness Probes & Rust Workspace Verification

To ensure Kubernetes `readinessProbe` checks verify real role readiness (not merely open TCP sockets):
- **Relays (`entry`, `middle`, `exit`):** `readinessProbe` and `startupProbe` invoke:
  `/usr/local/bin/relay-client --probe-noise 127.0.0.1:<PORT> --pubkey-toml /cfg/<role>.toml`
  This extracts only `public_key_hex` (`RelayConfig::read_public_key_from_toml_str`), generates an ephemeral `StaticKeypair`, completes a real authenticated `Noise_IK` handshake via `connect_noise_link` proving both Tokio scheduling and matching X25519 private-key ownership, and closes cleanly before allocating any circuit slot (`active_circuit_count()` unchanged).
- **Destination (`demo-dest`):** `readinessProbe` invokes `/usr/local/bin/relay-client --probe-http 127.0.0.1:9000`, sending `GET /health` with write-half shutdown and validating `HTTP/1.1 200` + `"\"status\":\"ok\""`.
- **Liveness Probes:** Use lightweight `/usr/local/bin/relay-client --probe 127.0.0.1:<PORT>`.

### Rust & Container Evidence Executed

1. **Cargo Verification (`$env:CARGO_INCREMENTAL='0'`):**
   - `cargo fmt --all -- --check` -> Exit `0`
   - `cargo clippy --offline --workspace --all-targets -- -D warnings` -> Exit `0` (`0` warnings)
   - `cargo test --offline --workspace` -> **`42 passed; 0 failed; 0 ignored`** across 6 crates:
     - `private-relay-protocol`: `10 passed; 0 failed`
     - `private-relay-crypto`: `6 passed; 0 failed`
     - `private-relay-network`: `5 passed; 0 failed` *(includes Day 6 secret-file resolution, omission, pubkey-only parsing & conflict test)*
     - `private-relay-relay`: `6 passed; 0 failed`
     - `private-relay-client`: `10 passed; 0 failed`
     - `private-relay-cli`: `5 passed; 0 failed` *(+2 new tests: `cli_probe_mode_validation_rejects_ambiguous_flags` & `cli_readiness_probes_and_secret_file_separation_e2e` testing real `--probe-http`, `--probe-noise` positive + mismatched-identity rejection, secret-file separation, and 3-hop E2E HTTP request)*
2. **Docker Image Rebuild & Regression Run:**
   - Rebuilt `private-relay:v0.1` (`sha256:c83bdbf98240645b14f63901807ddfad53eb9bc4a88e74da19cd08c738f83c89`, `32,648,000` bytes / `32.6 MB`).
   - Verified `/usr/local/bin/relay-client --help` inside `private-relay:v0.1` advertises `--probe-noise <HOST:PORT> --pubkey-toml <FILE>` and `--probe-http <HOST:PORT>`.
   - Re-ran `powershell -ExecutionPolicy Bypass -File .\demo\run-docker-demo.ps1 -SkipBuild`: all 4 daemon containers healthy, `12/12` 3-hop container scenarios passed, `circuit_hops=12` confirmed on all 3 relays, and clean `SIGTERM` + volume/network teardown completed.

---

## 5. Offline Manifest Validation & Live Test Status

| Check / Phase | Result | Exact Evidence / Explanation |
| :--- | :--- | :--- |
| `kubectl kustomize k8s/` | **VERIFIED (`Exit 0`)** | Rendered `26` YAML documents cleanly; verified `NONROOT=6`, `ROFS=7`, `DROP_ALL=7`, `NO_PRIVESC=7`, `SECCOMP=6`, zero committed private keys. |
| `kubectl apply --dry-run=client -k k8s/` | **FAILED (Cluster Absent)** | Fails on OpenAPI schema download (`failed to download openapi: the server has asked for the client to provide credentials`); `--validate=false` still fails API group discovery (`unable to recognize "k8s/": the server has asked for the client to provide credentials`). |
| Live `kubectl apply -k k8s/` & image loading (`Phase 7`) | **`NOT VERIFIED`** | No Kubernetes cluster running (`kubectl cluster-info` unreachable). Requires `kind load` / `minikube image load` / Docker Desktop K8s before applying. |
| Live `keygen-job` & Workload Readiness (`Phase 7`) | **`NOT VERIFIED`** | Cannot observe real Pod scheduling or kubelet `--probe-noise` / `--probe-http` execution without a running cluster. |
| Live In-Cluster 3-Hop `client-job` & SSRF Tests (`Phase 8`) | **`NOT VERIFIED`** | Service DNS multi-hop routing (`Client -> Entry -> Middle -> Exit -> Destination`) and negative SSRF target tests unexecuted in K8s. |
| Live Pod Resilience & Failover (`Phase 9`) | **`NOT VERIFIED`** | Deleting Middle Pod recovery (`kubectl delete pod`) and `replicas=0` fail-closed checks documented in [k8s/README.md](../k8s/README.md) but unexecuted. |
| Runtime CNI `NetworkPolicy` Enforcement (`Phase 5`) | **`NOT VERIFIED`** | Manifests (`8` policies) authored and rendered cleanly; actual packet drops depend on deploying onto a policy-enforcing CNI (Calico/Cilium/Antrea) rather than default kindnet/flannel. |

---

## 6. Resource Limits & Single-Replica Constraint (`Phase 10`)

- **Container Resource Budgets:**
  - Relays (`entry`, `middle`, `exit`): `requests: 50m CPU / 32Mi RAM`, `limits: 250m CPU / 128Mi RAM` (`tmp` `emptyDir` `sizeLimit: 8Mi`).
  - `destination`: `requests: 25m CPU / 16Mi RAM`, `limits: 200m CPU / 64Mi RAM`.
  - `client` Job: `requests: 25m CPU / 16Mi RAM`, `limits: 200m CPU / 64Mi RAM`.
  - `keygen` Job: initContainer `50m / 32Mi` (`200m / 64Mi` limit); publisher `50m / 32Mi` (`200m / 128Mi` limit), `keygen-work` `emptyDir` (`medium: Memory`, `sizeLimit: 4Mi`).
- **Why `replicas: 1` Is Mandatory in `v0.1`:**
  1. Each `RelayServer` authenticates links via a unique static `X25519` keypair pinned inside upstream `allowed_next_peers` and `ClientConfigFile`. Kubernetes `ClusterIP` round-robin across `replicas > 1` with distinct Pod keys causes `Noise_IK` `UnexpectedPeerIdentity` failures (or requires sharing identical static keys across replicas, weakening isolation).
  2. Active onion circuit keys and routing tables (`CircuitTable`) exist purely in local Pod RAM (`Zeroizing`). Scaling horizontally or restarting a Pod drops established circuits (`PeerDisconnected`), forcing clients to establish a fresh circuit against healthy relays.
  3. **Post-`v0.1` Path:** Horizontal scaling requires `StatefulSet` + headless Services with per-ordinal identities registered dynamically via a signed Coordinator directory (`Phase 6`).
