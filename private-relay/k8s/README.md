# Private-Relay Kubernetes Deployment (`k8s/`)

Kustomize-managed Kubernetes manifests deploying the verified five-component Private-Relay v0.1 architecture (`Client -> Entry -> Middle -> Exit -> Destination`) under strict **Pod Security Standards (`restricted`)**, per-node Secret separation, and cryptographic/HTTP readiness probes.

> **Verification Status Note (Day 6):**
> These manifests are validated cleanly with offline Kustomize rendering (`kubectl kustomize k8s/`). Because no live Kubernetes cluster was running on the Day 6 verification host, live cluster deployment, in-cluster E2E traffic, Pod deletion/resilience recovery, and CNI runtime `NetworkPolicy` enforcement remain **`NOT VERIFIED`** pending execution against a live cluster (see [DAY_6_KUBERNETES_REPORT.md](../docs/DAY_6_KUBERNETES_REPORT.md)).

---

## Architecture & Isolation

| Component | Manifests | Port | Secret Mount | Probe Method |
| --- | --- | --- | --- | --- |
| `destination` | `destination-deployment.yaml`, `destination-service.yaml` | `9000/TCP` | None | `relay-client --probe-http 127.0.0.1:9000` (`GET /health` HTTP 200 JSON) |
| `exit` | `exit-deployment.yaml`, `exit-service.yaml` | `9103/TCP` | `private-relay-exit-secret` -> `/run/secrets/private_key_hex` | `relay-client --probe-noise 127.0.0.1:9103 --pubkey-toml /cfg/exit.toml` |
| `middle` | `middle-deployment.yaml`, `middle-service.yaml` | `9102/TCP` | `private-relay-middle-secret` -> `/run/secrets/private_key_hex` | `relay-client --probe-noise 127.0.0.1:9102 --pubkey-toml /cfg/middle.toml` |
| `entry` | `entry-deployment.yaml`, `entry-service.yaml` | `9101/TCP` | `private-relay-entry-secret` -> `/run/secrets/private_key_hex` | `relay-client --probe-noise 127.0.0.1:9101 --pubkey-toml /cfg/entry.toml` |
| `client` | `client-job.yaml` | None | None | Runs one-shot E2E HTTPS-less onion request to `destination:9000/health` |
| `keygen` | `keygen-job.yaml` | None | Writes initial ConfigMaps & per-node Secrets | Ephemeral `Job` using namespace-scoped `Role` |

### Hardening Guarantees
- **PSS `restricted` Namespace:** `runAsNonRoot: true`, `runAsUser: 10001`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`.
- **Zero Secrets in Git:** `secrets.example.yaml` is intentionally excluded from `kustomization.yaml`. Relays refuse to start until unique per-deployment X25519 keys are provisioned.
- **No Secret Env Vars:** Private keys are mounted via `Secret` files (`/run/secrets/private_key_hex`, mode `0400`) and zeroed after `StaticKeypair` construction.
- **Single-Replica Constraint (v0.1):** Each relay Deployment keeps `replicas: 1` (`strategy.type: Recreate`) because v0.1 relays hold unique pinned X25519 keys and ephemeral RAM-only `CircuitTable` state.

---

## Prerequisites

1. A running Kubernetes cluster (`kind`, `minikube`, `k3d`, or Docker Desktop Kubernetes).
2. Local container image `private-relay:v0.1` built from `private-relay/Dockerfile`:
   ```powershell
   docker compose build
   ```
3. Make the image available inside your cluster nodes (because `imagePullPolicy: IfNotPresent` is configured):
   - **Docker Desktop Kubernetes:** uses host Docker image store automatically.
   - **kind:** `kind load docker-image private-relay:v0.1`
   - **minikube:** `minikube image load private-relay:v0.1`
   - **k3d:** `k3d image import private-relay:v0.1`
4. *(Optional for NetworkPolicy enforcement)* A NetworkPolicy-enforcing CNI plugin (Calico, Cilium, or Antrea). Default `kindnet` or `flannel` accepts `NetworkPolicy` YAML without enforcing traffic drops.

---

## Quick Start (PowerShell)

### 1. Preview Rendered Manifests Offline
```powershell
kubectl kustomize k8s/
```

### 2. Deploy Manifests & Provision Cryptographic Identities
```powershell
kubectl apply -k k8s/
kubectl wait -n private-relay --for=condition=complete job/private-relay-keygen --timeout=120s
```

<details>
<summary>Alternative: Airgapped Key Generation Without In-Cluster <code>alpine/kubectl</code> Pull</summary>

If your cluster cannot pull `alpine/kubectl:1.34.1`, generate split ConfigMaps and isolated key files locally into a temporary directory, apply them directly, and securely wipe the temp directory:

```powershell
$tmp = Join-Path $env:TEMP ("pr-k8s-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
docker run --rm -v "${tmp}:/out" --entrypoint /usr/local/bin/relay-keygen private-relay:v0.1 `
  --out-dir /out `
  --entry-addr private-relay-entry.private-relay.svc.cluster.local:9101 `
  --middle-addr private-relay-middle.private-relay.svc.cluster.local:9102 `
  --exit-addr private-relay-exit.private-relay.svc.cluster.local:9103 `
  --entry-listen 0.0.0.0:9101 --middle-listen 0.0.0.0:9102 --exit-listen 0.0.0.0:9103 `
  --allow-target private-relay-destination.private-relay.svc.cluster.local:9000 `
  --allow-private-targets-for-test --deny-loopback --split-dirs --key-file-path /run/secrets/private_key_hex

kubectl create configmap private-relay-entry-config -n private-relay --from-file=entry.toml="$tmp/entry/entry.toml" --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap private-relay-middle-config -n private-relay --from-file=middle.toml="$tmp/middle/middle.toml" --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap private-relay-exit-config -n private-relay --from-file=exit.toml="$tmp/exit/exit.toml" --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap private-relay-client-config -n private-relay --from-file=client.toml="$tmp/client/client.toml" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic private-relay-entry-secret -n private-relay --from-file=private_key_hex="$tmp/entry/entry.key" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic private-relay-middle-secret -n private-relay --from-file=private_key_hex="$tmp/middle/middle.key" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic private-relay-exit-secret -n private-relay --from-file=private_key_hex="$tmp/exit/exit.key" --dry-run=client -o yaml | kubectl apply -f -
Remove-Item -Recurse -Force $tmp
```

</details>

### 3. Restart Workloads to Pick Up Final Configs & Secrets, Then Wait for Readiness
```powershell
kubectl rollout restart -n private-relay deployment/private-relay-exit deployment/private-relay-middle deployment/private-relay-entry
kubectl wait -n private-relay --for=condition=available deployment --all --timeout=180s
```

### 4. Verify Three-Hop Circuit Execution
```powershell
kubectl wait -n private-relay --for=condition=complete job/private-relay-client --timeout=180s
kubectl logs -n private-relay job/private-relay-client
```

---

## Live Verification & Resilience Checklist

Once running inside a live cluster, verify:

1. **Pod Health & Probes:** `kubectl get pods -n private-relay -o wide` (all `READY 1/1`, zero restarts after keygen).
2. **Exit SSRF Protection:** Launch an ephemeral client override targeting `--url http://127.0.0.1:9000/health` or `--url http://169.254.169.254/latest/meta-data/` -> expected `PolicyDenied`.
3. **Middle Pod Deletion Recovery:**
   ```powershell
   kubectl delete pod -n private-relay -l app.kubernetes.io/component=middle
   kubectl wait -n private-relay --for=condition=available deployment/private-relay-middle --timeout=120s
   kubectl delete job -n private-relay private-relay-client
   kubectl apply -f k8s/client-job.yaml
   kubectl wait -n private-relay --for=condition=complete job/private-relay-client --timeout=120s
   ```
4. **Relay Unavailable Fail-Closed:**
   ```powershell
   kubectl scale deployment/private-relay-middle -n private-relay --replicas=0
   # Expect relay-client to fail closed rather than bypassing Middle or falling back to direct exit.
   kubectl scale deployment/private-relay-middle -n private-relay --replicas=1
   ```
5. **Cleanup:**
   ```powershell
   kubectl delete -k k8s/
   ```
