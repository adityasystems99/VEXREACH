# Private-Relay Protocol — Roadmap, MVP Scope & Status Tracker

---

## 1. Capability Implementation Matrix (Strict Honesty)

| Capability | Category | Status | Target Phase |
| :--- | :--- | :--- | :--- |
| Binary cell framing (`600B` total wire frames / `582B` plaintext) | Implemented Prototype (`Day 1`) | **Implemented & Tested (`10/10` protocol tests)** | Day 1 (`Complete`) |
| `Noise_IK` link channel + coordinated link rekeying (`3600s` / `1 GiB`) | Established Tech (`snow v0.9.6`) + `D-09` | **Implemented & Tested (`Day 3`, `6/6` crypto + `5/5` net tests)** | Day 3 (`Complete`) |
| `Noise_NK` telescopic hops + per-hop `ChaCha20-Poly1305` + `u64` replay | Established Tech + `D-07`/`D-08` | **Implemented & Tested (`Day 2`, `6/6` crypto tests)** | Day 2 (`Complete`) |
| Single Rust relay (`CircuitTable`, conn semaphore, bounded queues, SSRF + DNS timeout) | Implemented Prototype (`Day 2–3`) | **Implemented & Tested (`6/6` relay tests)** | Day 3 (`Complete`) |
| Standalone CLI binaries + 5-process Windows local demo (`demo/`) | Implemented Prototype (`Day 3`) | **Implemented & Tested (`3/3` CLI tests + log proof + `10/10` PS demo)** | Day 3 (`Complete`) |
| Multi-hop request & response routing (`Client → Entry → Middle → Exit → Dest`) | Implemented Prototype (`Day 2–3`) | **Implemented & Tested (`10/10` client E2E + `3/3` CLI tests)** | Day 3 (`Complete`) |
| Coordinator registry, operator diversity & failover | Proposed / Deferred | **Deferred** | Phase 6B |
| Privacy-preserving Prometheus aggregate metrics | Proposed / Deferred | **Deferred** | Phase 7 |
| Adversarial crypto, SSRF & DoS test harness | Proposed / Deferred | **Deferred (`cargo-fuzz`/`cargo-audit` not run)** | Phase 7 |
| Local Docker Compose 5-container deployment (`v0.1`) | Implemented Prototype (`Day 5`) | **Implemented & Tested (`12/12` container E2E + `private-relay:v0.1`)** | Day 5 (`Complete`) |
| Hardened Kubernetes Kustomize manifests, Secret separation & Noise/HTTP probes | Implemented Prototype (`Day 6`) | **Manifests & Rust Probes Verified (`kubectl kustomize` + `42/42` tests); Live Cluster `NOT VERIFIED`** | Day 6 (`Partial`) |
| Multi-host cloud / TLS deployment | Proposed / Deferred | **Deferred (Multi-host WAN/KMS not started)** | Phase 8 |
| Live backend-connected frontend / LLM operational assistant | Proposed / Deferred | **Deferred (Excluded from Day 3)** | Phase 9 |
| Sphinx constant-length `N`-hop headers / Cover traffic | Research Extension | **Experimental / Out of Scope for v0.1** | Beyond v0.1 |

---

## 2. MVP v0.1 Definition & Honest Privacy Boundary

### What `Private-Relay v0.1` (Phases 2–4) Will Demonstrate
1. A Rust client CLI/library initiating a 3-hop circuit across locally running `Entry`, `Middle`, and `Exit` processes on distinct `127.0.0.1` ports.
2. Encrypted `Noise_IK` peer links carrying uniform `600`-byte padded link frames.
3. Telescopic `Noise_NK` handshakes giving independent forward/backward `ChaCha20-Poly1305` keys per hop.
4. Multi-hop request forwarding to a local mock HTTP/echo destination server (with Exit DNS resolution & SSRF rejection of private IPs unless test flag enabled) and accurate response delivery back to the client.
5. Immediate circuit `DESTROY` cleanup and key zeroization upon peer disconnection, AEAD tampering, or sequence replay.
6. Automated unit and integration tests proving every state transition above.

### Privacy Properties `v0.1` **DOES** Establish (Upon Passing Tests)
- Single-relay cryptographic isolation: Entry never sees the Exit target or plaintext; Middle sees neither origin IP nor target; Exit never sees Client IP.
- Integrity and replay resistance at every individual hop over the circuit.
- Uniform outer packet framing across link sockets (preventing packet-type length leaks).

### Privacy Properties `v0.1` **DOES NOT** Establish
- **Does NOT defeat passive timing/volume correlation** if an observer watches both Client↔Entry and Exit↔Destination.
- **Does NOT defeat colluding `Entry + Exit` relays** in a small 3-node testbed.
- **Does NOT make a 3-node local setup production-ready or globally anonymous.**

---

## 3. Sequential Milestones

- **Phase 1 — Architecture & Technical Specification (Complete):** `PROTOCOL_SPEC.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `docs/TECH_DECISIONS.md`, `ROADMAP.md`, `README.md`.
- **Phase 2 — `protocol/` & `crypto/` Crates (Complete):** Wire framing codecs, `Noise_IK`/`Noise_NK` (`snow`), coordinated link rekeying (`D-09`), `HKDF-SHA256` key separation (`D-08`), monotonic `ChaCha20-Poly1305`, and crypto tests.
- **Phase 3 — `relay/` Engine & `network/` Transport (Complete):** Async Tokio parameterized `Entry`/`Middle`/`Exit` relay, `CircuitTable`, bounded channels, connection cap, hardened Exit SSRF policy, and failure cleanup.
- **Phase 4 — `client/`, `cli/` & 5-Process Local Integration (Complete for `v0.1`):** Standalone `relay-entry`, `relay-middle`, `relay-exit`, `relay-client`, `demo-dest`, and `relay-keygen` binaries + PowerShell multi-process Windows demo + internal security review (`SECURITY_REVIEW.md`).
- **Phase 5 — `coordinator/` Discovery & Recovery:** Axum directory API, signed descriptors, operator diversity checks, and circuit failover.
- **Phase 6 — Observability:** Aggregate Prometheus counters (strictly verified PII-free).
- **Phase 7 — Adversarial Security & Benchmark Suite:** Replay, tagging, slowloris backpressure, SSRF, DNS-leak probes, and latency/throughput benchmarks.
- **Phase 8 — Deployment:** Linux containers, firewall rules, non-root key management, operational security runbooks.
- **Phase 9 — Real Frontend Integration:** Connect only real verified backend APIs/telemetry, labeling prototypes cleanly.

---

## 4. Planned Workspace Structure (Created Incrementally — Zero Empty Crates)

```text
private-relay/
├── Cargo.toml             # 6-crate Cargo workspace (`v0.1`)
├── README.md
├── PROTOCOL_SPEC.md
├── THREAT_MODEL.md
├── ARCHITECTURE.md
├── SECURITY_DESIGN.md
├── SECURITY_REVIEW.md     # Day 3 focused 16-point internal security review
├── ROADMAP.md
├── demo/                  # Day 3 multi-process PowerShell scripts & config templates
├── docs/
│   └── TECH_DECISIONS.md
└── crates/
    ├── protocol/          # Stateless wire cells, framing & chunking
    ├── crypto/            # Noise_IK / Noise_NK + link rekeying + ChaCha20-Poly1305 + zeroize
    ├── network/           # Config validation, SSRF policy & async Noise TCP links
    ├── relay/             # Async parameterized Entry / Middle / Exit server
    ├── client/            # Telescopic 3-hop client & E2E integration tests
    ├── cli/               # Standalone binaries (`relay-*`, `demo-dest`, `relay-keygen`)
    └── coordinator/       # Phase 5 (Deferred — not created in v0.1)
```
