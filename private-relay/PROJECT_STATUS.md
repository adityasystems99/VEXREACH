# Private-Relay Project Status (`PROJECT_STATUS.md`)

**Last Updated:** `2026-11-26`  
**Current Phase:** **Day 2 Complete → Ready for Day 3 (CLI Runner, Local Reproducible Demo, Soak/Reliability & Release Packaging)**  
**Overall Implementation State:** Core Protocol, Cryptography, Async TCP Transport, Parameterized Relay Engine, and 3-Hop Client Implemented & Verified (`29/29` workspace tests passing; `clippy -D warnings` clean; CLI binaries & Day 3 demo harness next)

---

## Milestone Progress

| Phase | Milestone | Status | Artifacts / Evidence |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Research, Threat Model, Architecture, Protocol Spec | **Complete** | [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md), [THREAT_MODEL.md](./THREAT_MODEL.md), [ARCHITECTURE.md](./ARCHITECTURE.md), [SECURITY_DESIGN.md](./SECURITY_DESIGN.md) |
| **Phase 2** | Requirements, Stack Evaluation, MVP Scope, Continuity Logs | **Complete** | [TECH_STACK.md](./TECH_STACK.md), [MVP_SCOPE.md](./MVP_SCOPE.md), [DECISIONS.md](./DECISIONS.md), [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) |
| **Phase 3 (Day 1)** | Architecture Freeze (`D-01`, `D-02`, `D-07`), Rust Workspace & `crates/protocol` | **Complete (`Verified`)** | [Cargo.toml](./Cargo.toml), [crates/protocol](./crates/protocol/Cargo.toml), [tests/protocol_tests.rs](./crates/protocol/tests/protocol_tests.rs) (`10/10` passed) |
| **Phase 4 (Day 2)** | Cryptography (`crypto`), Async Link Transport & SSRF Policy (`network`), Relay Engine (`relay`), and 3-Hop Client & E2E Tests (`client`) | **Complete (`Verified`)** | `crates/crypto` (`4/4`), `crates/network` (`3/3`), `crates/relay` (`4/4`), `crates/client` (`8/8`); full workspace `29/29` passed + `clippy -D warnings` clean |
| **Phase 4–5 (Day 3)** | CLI Demo Binaries, TOML Fixtures, Reliability/Soak Harness & v0.1 Release Verification | **Not Started (`Next`)** | Standalone local binary demo, config samples, soak tests & final v0.1 release docs |
| **Phase 5–12** | Discovery, Failover, Prometheus Metrics, Frontend, Docker/K8s/LLM Readiness | Planned / Deferred | Strictly deferred beyond v0.1 prototype |

---

## Capability Implementation Breakdown

- **Implemented & Tested (`Day 1`):**
  - Approved architecture freeze: `D-01` (bounded `<= 64 KiB` request/response), `D-02` (exact `600`-byte total on-wire Noise frame = `2B len 598 + 582B plaintext + 16B MAC`), `D-07` (end-to-end hop AEAD AAD omitting link-local `CircuitId`).
  - Pure-Rust `private-relay-protocol` crate (`10/10` automated boundary/malformed-input tests).
- **Implemented & Tested (`Day 2`):**
  - `private-relay-crypto` (`D-08` Noise_NK transcript-bound exporter, `Noise_IK` `600B` link framing via `snow v0.9.6`, per-hop `ChaCha20-Poly1305`, `HKDF-SHA256`, `ZeroizeOnDrop`; `4/4` tests).
  - `private-relay-network` (`RelayConfig` TOML serde & validation, `DestinationPolicy` DNS-once + SSRF deny list, async `Noise_IK` client/server links handling partial reads/writes via `TrickleStream`; `3/3` tests).
  - `private-relay-relay` (parameterized `Entry`/`Middle`/`Exit` `RelayServer`, link multiplexing, cancellation-safe downstream dials, role/peer allowlist enforcement, global & Entry per-IP circuit limits, bounded `mpsc` backpressure, Exit request reassembly & bounded response handling; `4/4` tests).
  - `private-relay-client` (`RelayClient::connect_three_hop`, `ClientCircuit::send_request`/`close`, full 3-relay local E2E `0B`/`small`/`64 KiB` round-trips, SSRF denial, closed destination, slowloris timeout, oversized response abort, missing relay failure cleanup, mid-circuit relay crash cleanup, bitflip MITM rejection, and log redaction test verifying zero IPs/destinations/keys/payloads in `tracing`; `8/8` tests).
- **Not Yet Implemented (`Scheduled Day 3`):** Standalone CLI runner binaries for relay/client processes, sample TOML config scripts, automated time-based Noise link rekey (`3600s` / `1 GiB` rotation), multi-client soak harness, and v0.1 release runbook.
- **Explicitly Deferred Until User Authorization:** Live Kubernetes cluster/Helm deployments; live LLM provider credentials.
