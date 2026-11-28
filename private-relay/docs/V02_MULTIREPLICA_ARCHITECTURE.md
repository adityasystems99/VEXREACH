# PRIVATE RELAY v0.2 — MULTI-REPLICA DISTRIBUTED ARCHITECTURE & PROTOTYPE REPORT

**Date:** 2026-11-28  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Status Summary:** Single-Replica Coupling & Security Analysis + Isolated 6-Node Multi-Replica Prototype ([multireplica_prototype_tests.rs](../crates/client/tests/multireplica_prototype_tests.rs)) **`VERIFIED OFFLINE`** | Kubernetes Signed Coordinator + `StatefulSet` Rollout **`PROPOSED`** *(Existing production-path `k8s/` Deployments remain intentionally unchanged at `replicas: 1` per rule `4.4`.)*

---

## 1. Analysis of Current Single-Replica Constraints (`KI-10`)

Inspecting `crates/protocol`, `crates/crypto`, `crates/network`, `crates/relay`, and `k8s/` identifies **eight concrete state/identity couplings** that pin Private Relay `v0.1`/`v0.2` Deployments to `replicas: 1`:

1. **Per-Instance Static Identity (`StaticKeypair`):** Every relay Pod loads one static `X25519` keypair (`/run/secrets/private_key_hex`), authenticated by peers during both `Noise_IK` link setup (`expected_remote_pub`) and `Noise_NK` hop setup.
2. **Link-Local `CircuitId` Ownership:** `CircuitId` only identifies a circuit within a single TCP link (`routes: HashMap<CircuitId, mpsc::Sender<Cell>>` in `spawn_inbound_link_loop` and `OutboundLinkHandle::routes`), allocated per link via `AtomicU32` + MSB initiator bit (`0x8000_0000`).
3. **Ephemeral Per-Task Cryptographic State:** `HopCipherPair` (`forward`/`backward` 256-bit keys and strict FIFO `next_seq: u64` counters with `ZeroizeOnDrop`) lives exclusively inside the local heap/stack of one spawned Tokio `run_circuit_task` future.
4. **Exit Replay Table Locality:** `used_request_ids: HashSet<u32>` + `VecDeque<u32>` (`4096` window) and `active_dest_task` reside strictly inside `run_exit_circuit_task` RAM.
5. **TCP Connection Ownership & Pooled Links:** `OutboundLinkHandle` pools outbound connections in `RelayRuntime.outbound_links` keyed by `(addr, [u8; 32] pubkey)`. Once established, a circuit stays pinned to one specific `(upstream TCP link, downstream OutboundLinkHandle)` pair for its entire lifetime.
6. **Hard-Coded Hop Topology Allowlists:** `RelayConfig.allowed_next_peers` binds `Entry` -> explicit `Middle` `(addr, pub_key)` descriptors and `Middle` -> `Exit` descriptors; `ExtendDirective` names explicit next-hop `(next_hop_addr, next_hop_pub)`.
7. **ClusterIP Round-Robin Incompatibility:** Kubernetes `ClusterIP` Services (`private-relay-entry:9101`, `middle:9102`, `exit:9103`) distribute new TCP flows arbitrarily across backend Pods. If replicas hold distinct keys, clients/upstream relays hit mismatched `X25519` public keys (`UnexpectedPeerIdentity` / `HandshakeFailed`).
8. **Shutdown & Recovery Semantics:** On Pod termination (`SIGTERM` / delete), local circuits intentionally emit `DestroyReason::Normal` and zeroize `HopCipherPair` keys in RAM (`exit` / `middle` never persist session keys across restarts).

---

## 2. Comparative Evaluation of Candidate Architectures

| Dimension | A: Multiple Independent Pods behind ClusterIP Service | B: Client-Side Endpoint Selection (`StatefulSet` / Directory) | C: Stateful Circuit-to-Instance L4/L7 Gateway Routing | D: Dedicated Per-Replica Identity & Persistent Session Ownership | E: Distributed State Synchronization (KV / Raft) |
|---|---|---|---|---|---|
| **Security** | **Broken without key-sharing** *(forces shared global key, violating secret isolation; Pod compromise compromises all replicas)* | **High** *(unique keypair per instance; `Noise_IK`/`Noise_NK` pins exact instance pubkey)* | **Medium-High** *(if gateway terminates outer mux only without touching onion keys)* | **High** *(unique keypair + `ZeroizeOnDrop` strictly local to owning instance)* | **Low/Unsafe for Onion Keys** *(exporting ephemeral `HopCipherPair` keys/nonces across Raft breaks forward secrecy & `ZeroizeOnDrop`)* |
| **Privacy** | **Poor** *(cross-Pod mismatch leaks errors or encourages shared static secrets)* | **High** *(entry/middle/exit diversity prevents single-operator/node concentration)* | **Medium** *(single VIP gateway observes Entry connection timing across replicas)* | **High** *(each relay remains blind beyond adjacent hop + per-Pod identity)* | **Poor** *(replication bus creates central metadata plane correlating active circuits)* |
| **Circuit Continuity** | **Broken** *(ClusterIP re-balances reconnects/extensions to wrong Pod)* | **Clean per-instance** *(pinned per circuit for lifetime; retry builds fresh circuit)* | **Clean if sticky** *(requires consistent hash / token before `Noise_IK`)* | **Clean per-instance** *(circuit pinned to exact TCP link + `CircuitId`)* | **Illusory** *(mid-flight TCP sockets still drop on Pod crash; seq race causes AEAD desync)* |
| **Failure Recovery** | Unreliable under scale-out | Client builds new 3-hop path over surviving replicas | Gateway removes unhealthy Pod cleanly | Re-dial picks surviving healthy replica | High split-brain / stale-nonce risk (`u64` FIFO collision -> catastrophic ChaCha20 nonce reuse!) |
| **Complexity & Overhead** | Low (doesn't work safely) | Low-Medium (signed descriptor list) | High (custom L4/L7 sticky proxy) | Low (matches existing `RelayRuntime` model) | Extreme + High latency on every cell/seq update |
| **Scaling** | None safely | Linear by adding independent Pods | Linear behind gateway pool | Linear across `(Entry_i, Middle_j, Exit_k)` pairs | Bottlenecked on consensus write latency |
| **New Trust Assumptions** | Shared Pod secret across replicas | Signed Directory / Coordinator pubkey pinned by Clients & Relays | Trusted ingress L4 proxy / consistent-hash router | Signed Registry distributing `(id, pod_fqdn, role, pubkey)` | Trusted state store holds live symmetric session keys |

---

## 3. Security Implications Deep Dive

1. **Why Shared Global Private Keys (`Option A`) Must Be Rejected:**
   - Sharing one static `X25519` keypair across `replicas: N` Pods enables passive impersonation across instances, expands blast radius (`1` compromised Exit Pod exposes identity keys of all Exit replicas), and fails cryptographic identity auditability. Even with shared keys, `Entry` or `Middle` opening a second TCP connection lands on a different Pod lacking `CircuitId` state unless every Pod shares ephemeral circuit keys too.
2. **Why Distributed Session Key Synchronization (`Option E`) Violates AEAD Nonce Invariants:**
   - `HopCipherState` relies on strict monotonic `next_seq: u64` (`nonce = [0,0,0,0] || seq_be`) under `ChaCha20-Poly1305`. Asynchronous or delayed replication of `next_seq` after failover can cause two replicas to encrypt different backward cells with the **same key and nonce**, breaking `ChaCha20-Poly1305` confidentiality and Poly1305 one-time key secrecy completely.
3. **Cross-Instance Circuit Confusion & Identity Substitution:**
   - Because every `CircuitId` is link-local and `HopHandshake` binds `transcript_hash` + the responder's static `X25519` keypair, pinning each instance to a unique DNS endpoint + public key prevents cross-instance hijacking: `Noise_IK` fails closed at `LinkInitiator::finish_with_msg2` (`UnexpectedPeerIdentity`) if DNS/network misroutes traffic to another replica, and `Noise_NK` `HopHandshake` fails at `msg1`/`msg2` if an upstream relay attempts Man-in-the-Middle substitution.
4. **Correlation & Availability Tradeoffs:**
   - Distributing circuits uniformly across `N` independent Entry, Middle, and Exit Pods reduces traffic concentration per Pod. However, directory freshness windows and uneven client path weighting can create fingerprinting opportunities unless Coordinator directories use coarse snapshots, operator-diversity placement (`KI-02`), and uniform client sampling across verified healthy replicas.

---

## 4. Recommendation & Prototype Decision (`VERIFIED OFFLINE` + `PROPOSED`)

### Recommended Architecture: Option B + Option D (Unique Per-Instance Identity + Stateful Endpoint Pinning)

1. **Identity Model:** Each relay Pod owns a distinct ephemeral or operator-provisioned `StaticKeypair` (never shared across replicas), running inside Kubernetes `StatefulSet`s (`private-relay-entry-{0..N}`, `middle-{0..N}`, `exit-{0..N}`) addressed via Headless Services (`clusterIP: None`), so every replica has a stable DNS FQDN matching its pinned `X25519` public key.
2. **Session Ownership:** Keep all `CircuitTable`, `HopCipherPair`, `used_request_ids`, and `LinkSession` state strictly in the owning Pod's local memory (`ZeroizeOnDrop`), zero-shared, and fail-closed on Pod death.
3. **Control Plane (`PROPOSED` Phase 11+):** Add a signed **Coordinator Descriptor Registry** (or Kubernetes `EndpointSlice`/Secret watcher publishing signed `[PeerDescriptor]` manifests with monotonic epochs and operator-IDs). Clients select `(entry_i, middle_j, exit_k)` from distinct operators and connect directly to `entry_i`; `Entry_i` maintains persistent multiplexed `OutboundLinkHandle` trunks to `Middle_j` (`(fqdn, pubkey)`), and `Middle_j` to `Exit_k`.

### Verified Isolated Prototype ([multireplica_prototype_tests.rs](../crates/client/tests/multireplica_prototype_tests.rs))

Without modifying existing `k8s/` production-path `replicas: 1` manifests, an isolated **6-node multi-replica cluster (`2x Entry`, `2x Middle`, `2x Exit`)** was implemented and verified (`VERIFIED OFFLINE`, test `multireplica_prototype_isolated_routing_identity_pinning_and_failover` passed in `1.50s`):
- Verified all `6` relay instances hold unique `X25519` public keys (`0` shared secrets).
- Executed concurrent traffic across crossed instance paths (`exit-0` <-> `middle-1` <-> `entry-0` and `exit-1` <-> `middle-0` <-> `entry-1`).
- Verified cross-instance identity substitution (`entry-0` addr paired with `entry-1` public key) and unlisted route targets fail closed immediately.
- Terminated `middle-0` mid-session: confirmed circuits pinned to `middle-0` terminate cleanly while concurrent circuits pinned to `middle-1` remain **100% uninterrupted** (including SSRF enforcement), new failover circuits seamlessly route over `(entry-1 -> middle-1 -> exit-1)`, and post-test `active_circuit_count()` returns to `0` across all surviving replicas.
