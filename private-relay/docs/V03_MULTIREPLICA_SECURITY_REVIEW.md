# VEXREACH Private Relay v0.3 — Multi-Replica Security Architecture Review (Track 6)

**Project:** VEXREACH Private Relay (Unaudited Research Prototype)  
**Scope:** Security review of v0.2 multi-replica design (`docs/V02_MULTIREPLICA_ARCHITECTURE.md`), `MultiReplicaPrototypeCluster` (`crates/client/tests/multireplica_prototype_tests.rs`), and Kubernetes deployment constraints (`k8s/*-deployment.yaml`, `k8s/network-policy.yaml`)  
**Scaling Decision Status:** **`PROPOSED` for production/Kubernetes cluster scaling** (v0.1–v0.3 cluster manifests remain intentionally `replicas: 1` with `strategy.type: Recreate`; only isolated multi-instance cryptographic routing behavior is `VERIFIED OFFLINE` in Rust integration tests).

---

## 1. Current Single-Replica Architecture Constraints (`KI-10`)

Inspecting `k8s/entry-deployment.yaml`, `k8s/middle-deployment.yaml`, `k8s/exit-deployment.yaml`, `k8s/entry-service.yaml`, `k8s/middle-service.yaml`, and `k8s/exit-service.yaml` confirms why naive horizontal scaling (`replicas > 1` behind `ClusterIP` Services) breaks both protocol correctness and security:

1. **Identity-Pinned Noise Framing (`PeerDescriptor`):**
   - Clients and hops authenticate peers via `PeerDescriptor { id: String, role: RelayRole, addr: String, public_key_hex: String }` (`crates/network/src/config.rs`).
   - `Noise_NK_25519_ChaChaPoly_SHA256` circuit handshakes authenticate the responder against a specific static X25519 key (`s`), and `Noise_XX` link handshakes bind mutual static identities.
   - If two relay Pods shared one `ClusterIP` DNS name (`private-relay-entry.private-relay.svc.cluster.local`) with distinct identities, round-robin load balancing breaks handshake verification (~50%+ failure rate).
   - Conversely, sharing one static private key across multiple Pods widens compromise blast radius, weakens forward secrecy isolation per host, and still fails TCP affinity.
2. **Process-Local Stateful `CircuitTable`:**
   - Every established circuit creates hop-local cryptographic state (`HopSession` / `CircuitTable` entries) tied to that specific relay process and persistent hop link.
   - Routing packet 1 to Pod A and circuit cells to Pod B guarantees `CircuitNotFound` / drop.

---

## 2. Security Analysis of `Option B + Option D` (Unique Per-Instance Identity + Stateful Endpoint Pinning)

Based on `V02_MULTIREPLICA_ARCHITECTURE.md` and `MultiReplicaPrototypeCluster` (verified offline across 2 Entry, 2 Middle, and 2 Exit independent instances in `multireplica_prototype_tests.rs`):

| Threat / Property | Security Analysis Under Unique Per-Pod Identities + Endpoint Pinning | Status |
|---|---|---|
| **Identity Ownership & Compromise Blast Radius** | Each replica generates its own keypair inside isolated `Secret` / tmpfs memory (never cloned across pods). Compromising `exit-2` exposes zero static keys for `exit-1`, `middle-*`, or `entry-*`. Requires `StatefulSet` (`relay-exit-0`, `relay-exit-1`) or per-replica headless DNS endpoints (`pod-name.headless-svc.namespace.svc.cluster.local`), never a shared round-robin `ClusterIP`. | `PROPOSED` (Design), `VERIFIED OFFLINE` (Routing logic) |
| **Descriptor Authenticity & Tampering** | Unsigned TOML/JSON `PeerDescriptor` lists allow any directory operator or MitM to substitute attacker pubkeys/addrs (eclipse or active Sybil circuit hijack). Production multi-replica discovery MUST distribute signed descriptors (`Ed25519` authority signature or M-of-N consensus threshold) covering `{id, role, addr, static_x25519_pk, epoch, issued_at, expires_at}`. | `PROPOSED` |
| **Descriptor Replay & Expiration** | Without `issued_at`, `expires_at`, and strictly monotonic `descriptor_seq` / `epoch`, an attacker can replay revoked descriptors pointing to compromised or retired Pods whose keys were leaked later. Clients MUST reject stale epochs and expired descriptors fail-closed. | `PROPOSED` |
| **Monotonic Key Rotation / Epoch Rules** | Rotations must enforce: (1) overlapping grace window (`epoch N` read-only drain + `epoch N+1` active for new circuits), (2) never decrementing persisted `min_accepted_epoch`, (3) explicit `Zeroizing` scrub of retired `StaticKeypair` once active drained circuits hit `0` or timeout expires. | `PROPOSED` |
| **Circuit-to-Relay Affinity & Failover** | Once a client constructs `[PeerDescriptor; 3]` (`route(e_idx, m_idx, x_idx)`), all 3 Noise NK layers and `RelayFrame` cells remain pinned to those exact `(addr, public_key)` endpoints for the life of the circuit (`CircuitId`). On mid-circuit Pod failure, the client MUST tear down locally and build a **fresh circuit with new ephemeral keys** (`Option D`), never migrating half-encrypted state across pods. | `VERIFIED OFFLINE` (Test) |
| **Coordinator / Directory TCB Concentration** | A centralized K8s ConfigMap / control-plane coordinator deciding client routes or issuing descriptors becomes a single Trust Computing Base (TCB): a compromised coordinator could force all clients through colluding `(entry-evil, middle-evil, exit-evil)` tuples (Sybil / traffic-correlation attack). Mitigation: separate directory publishers per trust domain or require multi-signer directory consensus before accepting new `PeerDescriptor` entries. | `PROPOSED` |
| **Descriptor Substitution & Stale Registry Cleanup** | If a Pod is replaced (`kubectl delete pod`) while preserving its old endpoint DNS name, the new Pod generates a fresh keypair (or loads rotated secret) causing an immediate fail-closed `Noise` static key mismatch unless the directory reflects the new key; health checks (`--probe-noise` against the advertised public key) naturally quarantine misconfigured Pods before traffic shift. Stale entries must expire via hard TTL + active Noise probe liveness. | `PROPOSED` |
| **Cross-Replica State & Link Isolation** | Replicas must share **zero** mutable state (`CircuitTable`, Noise nonces, link keys, replay caches). Attempting distributed Redis/etcd synchronization of AEAD nonces risks fatal ChaCha20-Poly1305 `(key, nonce)` reuse across concurrent writers on split-brain. Strictly forbidden by design. | `PROPOSED` (Invariant) |

---

## 3. Centralized Coordinator vs. Decentralized Discovery Trade-offs

| Dimension | Centralized Signed Directory (e.g., K8s Controller / ConfigMap Signer) | Decentralized / Multi-Authority Consensus (Tor-style Directory Authorities) |
|---|---|---|
| **Operational Complexity** | Low (single operator controller signing descriptor bundles) | High (distributed voting, quorum management, skew tolerance) |
| **Compromise Blast Radius** | High (single directory key compromises route selection / Sybil resistance) | Lower (requires corrupting `>= quorum` independent signers to inject malicious relay) |
| **Partition / Consistency Behavior** | Fast convergence; single point of availability if not HA | Tolerates individual authority outage; slower descriptor propagation (`consensus_valid_after`) |
| **Timing / Partitioning Attacks** | Can selectively serve partitioned views (`route fingerprinting`) if unauthenticated | Requires deterministic canonical snapshot hashes across all clients so clients do not leak distinguishers via differing directory views |
| **Suitability for Private Relay** | Acceptable for **private enterprise/lab overlays** (single trust operator) | Necessary before **multi-tenant or adversarial public deployments** |

> [!WARNING]
> **Critical Privacy Warning (`NOT VERIFIED` against traffic correlation):** Even with signed directories and multi-replica failover, serving *different* subset views of the directory to different clients enables **route-fingerprinting attacks**, allowing an adversary watching Entry/Exit links to link client sessions by their candidate relay subset. All clients in a shared anonymity set must fetch the same canonical signed consensus snapshot.

---

## 4. Required Descriptor & Manifest Evolution Before Unlocking `replicas > 1`

Before modifying `k8s/*-deployment.yaml` (`replicas: 1`) for multi-replica Kubernetes production:

1. **Extend `PeerDescriptor` Schema (`PROPOSED`):**
   - Add `epoch: u64`, `issued_at_unix: u64`, `expires_at_unix: u64`, `weight: u16`, `signature_ed25519_hex: String`, and `signer_key_id: String`.
   - Clients fail closed if signature verification fails, `now > expires_at_unix`, or `epoch < last_seen_epoch[id]`.
2. **Switch Kubernetes Topology from `Deployment` + `ClusterIP` to `StatefulSet` + Headless `Service`:**
   - Give every Pod deterministic ordinal DNS (`private-relay-exit-0.private-relay-exit-headless...`), unique per-ordinal secret volume, and `NetworkPolicy` labels matching inter-hop role traffic (`entry -> middle -> exit -> destination`).
3. **Preserve Strict Failover Non-Correlation:**
   - Limit consecutive retry storms (`max_failover_attempts`), rotate paths across distinct failure domains, and avoid deterministic fallback to a single backup tuple.

---

## 5. Verdict

- **Multiplexing / Failover Logic:** `VERIFIED OFFLINE` in `crates/client/tests/multireplica_prototype_tests.rs` (client pins exact `[PeerDescriptor; 3]`, detects replica failure without panicking, and reconstructs fresh circuits via healthy alternate replicas).
- **Cluster Scaling Manifests:** Intentionally kept at `replicas: 1` (`PROPOSED` for v0.4+) because signed expiring descriptors, monotonic epoch anti-rollback, and `StatefulSet` headless identity addressing remain unimplemented in runtime binaries.
