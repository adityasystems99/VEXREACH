# Private-Relay Protocol — Roadmap, MVP Scope & Status Tracker

---

## 1. Capability Implementation Matrix (Strict Honesty)

| Capability | Category | Status | Target Phase |
| :--- | :--- | :--- | :--- |
| Binary cell framing (`600B` total wire frames / `582B` plaintext) | Implemented Prototype (`Day 1`) | **Implemented & Tested (`10/10` tests passing)** | Day 1 (`Complete`) |
| `Noise_IK` link channel + `Noise_NK` telescopic hop exchange | Established Tech + Hybrid Composition | **Implemented & Tested (`Day 2`, `4/4` crypto + `3/3` network tests)** | Day 2 (`Complete`) |
| Per-hop `ChaCha20-Poly1305` + `u64` replay sequence enforcement | Established Tech | **Implemented & Tested (`Day 2`, `4/4` crypto tests)** | Day 2 (`Complete`) |
| Single Rust relay (`CircuitTable`, bounded queues, SSRF check) | Proposed Implementation | **Implemented & Tested (`Day 2`, `4/4` relay tests)** | Day 2 (`Complete`) |
| Local 3-hop forwarding (`Client → Entry → Middle → Exit → Dest`) | Proposed Implementation | **Implemented & Tested (`Day 2`, `8/8` E2E tests)** | Day 2 (`Complete`) |
| Response routing back along circuit | Proposed Implementation | **Implemented & Tested (`Day 2`, `8/8` E2E tests)** | Day 2 (`Complete`) |
| Coordinator registry, operator diversity & failover | Proposed / Deferred | **Planned** | Phase 5 |
| Privacy-preserving Prometheus aggregate metrics | Proposed / Deferred | **Planned** | Phase 6 |
| Adversarial crypto, SSRF & DoS test harness | Proposed / Deferred | **Planned** | Phase 7 |
| Multi-host Docker / TLS deployment | Proposed / Deferred | **Planned** | Phase 8 |
| Live backend-connected frontend visualizer | Proposed / Deferred | **Planned** | Phase 9 |
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

- **Phase 1 — Architecture & Technical Specification (Complete in Current Step):** `PROTOCOL_SPEC.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `docs/TECH_DECISIONS.md`, `ROADMAP.md`, `README.md`.
- **Phase 2 — `protocol/` & `crypto/` Crates:** Define wire framing codecs, `Noise_IK`/`Noise_NK` wrappers (`snow`), HKDF key separation, strict monotonic AEAD ciphers, and adversarial crypto unit tests (`cargo test`).
- **Phase 3 — `relay/` Single-Hop Engine:** Build async Tokio relay supporting `Entry`/`Middle`/`Exit` config, `CircuitTable`, bounded channels, SSRF policy, and failure cleanup.
- **Phase 4 — `client/` & Multi-Hop End-to-End Integration:** Run `Client → Entry → Middle → Exit → Local Dest` locally on separate Windows ports with full automated E2E tests.
- **Phase 5 — `coordinator/` Discovery & Recovery:** Axum directory API, signed descriptors, operator diversity checks, and circuit failover.
- **Phase 6 — Observability:** Aggregate Prometheus counters (strictly verified PII-free).
- **Phase 7 — Adversarial Security & Benchmark Suite:** Replay, tagging, slowloris backpressure, SSRF, DNS-leak probes, and latency/throughput benchmarks.
- **Phase 8 — Deployment:** Linux containers, firewall rules, non-root key management, operational security runbooks.
- **Phase 9 — Real Frontend Integration:** Connect only real verified backend APIs/telemetry, labeling prototypes cleanly.

---

## 4. Planned Workspace Structure (Created Incrementally — Zero Empty Crates)

```text
private-relay/
├── Cargo.toml             # Added in Phase 2 once crates exist
├── README.md
├── PROTOCOL_SPEC.md
├── THREAT_MODEL.md
├── ARCHITECTURE.md
├── ROADMAP.md
├── docs/
│   └── TECH_DECISIONS.md
├── crates/
│   ├── protocol/          # Phase 2: stateless wire cells & serialization
│   ├── crypto/            # Phase 2: Noise_IK / Noise_NK + ChaCha20-Poly1305 + zeroize
│   ├── relay/             # Phase 3: async Entry / Middle / Exit server
│   ├── client/            # Phase 4: telescopic circuit builder & request client
│   └── coordinator/       # Phase 5: signed relay directory (added only in Phase 5)
└── tests/                 # Phase 4 & 7: multi-hop E2E & adversarial tests
```
