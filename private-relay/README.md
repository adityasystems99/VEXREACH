# Private-Relay Protocol

A research-oriented, 3-hop privacy-preserving relay overlay (`Client → Entry → Middle → Exit → Destination`) engineered in Rust with Noise Protocol handshakes and per-hop authenticated encryption.

> **Current Phase:** **Phase 1 & Phase 2 Complete → Ready for Phase 3 (`Cargo` Workspace & First Crate)**  
> **Code Status:** Architecture, cryptographic design, threat model, MVP requirements, and continuity logs are complete (`0` Rust implementation crates coded yet).

---

## Project Index

### Protocol, Threat Model & Architecture (`Phase 1`)
- [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md) — Wire framing (`600B` outer Noise link frames, `9B` cell headers), telescopic `Noise_NK` circuits, `ChaCha20-Poly1305` layering, replay rules, and limitations.
- [SECURITY_DESIGN.md](./SECURITY_DESIGN.md) — Primitive selection, `HKDF-SHA256` directional key separation, deterministic counter nonces, SSRF/DNS bounds, and log redaction rules.
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Analysis of 9 threat categories + verification tests.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — Trust boundaries, RAM state tables, and 6 Mermaid diagrams (architecture, trust zones, circuit build, request flow, response flow, failure teardown).

### Stack & MVP Requirements (`Phase 2`)
- [TECH_STACK.md](./TECH_STACK.md) & [docs/TECH_DECISIONS.md](./docs/TECH_DECISIONS.md) — Stack evaluation (`Rust`, `Tokio`, `snow`, RustCrypto, TCP vs QUIC, TOML, deferred Axum/PostgreSQL/Prometheus/Docker).
- [MVP_SCOPE.md](./MVP_SCOPE.md) — `FR-01`..`FR-08`, hard memory/circuit limits, targets vs. claims, and privacy boundaries.

### Continuity & Tracking Files
- [PROJECT_STATUS.md](./PROJECT_STATUS.md) — Current phase and completed/pending/deferred breakdown.
- [DECISIONS.md](./DECISIONS.md) — Architectural decision log (`D-01`..`D-06`).
- [ROADMAP.md](./ROADMAP.md) — Phase 1–12 roadmap and capability status matrix.
- [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) — Open limitations, correlation risks, and SSRF/TOCTOU constraints.
- [TEST_RESULTS.md](./TEST_RESULTS.md) — Verified environment checks and future test results.
- [CHANGELOG.md](./CHANGELOG.md) — Chronological record of specifications and releases.
