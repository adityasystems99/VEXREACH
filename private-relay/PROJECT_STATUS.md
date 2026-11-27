# Private-Relay Project Status (`PROJECT_STATUS.md`)

**Last Updated:** `2026-11-27`  
**Current Phase:** **Day 3 Complete — Private-Relay `v0.1` Prototype Verified (`40/40` workspace tests + 5-process Windows demo passing)**  
**Overall Implementation State:** Complete 6-crate workspace (`protocol`, `crypto`, `network`, `relay`, `client`, `cli`), coordinated Noise link rekeying (`D-09`), hardened SSRF/DNS-timeout/keypair/connection caps, multi-process Windows demo (`demo/`), and classified internal security review ([SECURITY_REVIEW.md](./SECURITY_REVIEW.md)). **Not audited externally / not production-ready.**

---

## Milestone Progress

| Phase | Milestone | Status | Artifacts / Evidence |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Research, Threat Model, Architecture, Protocol Spec | **Complete** | [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md), [THREAT_MODEL.md](./THREAT_MODEL.md), [ARCHITECTURE.md](./ARCHITECTURE.md), [SECURITY_DESIGN.md](./SECURITY_DESIGN.md) |
| **Phase 2** | Requirements, Stack Evaluation, MVP Scope, Continuity Logs | **Complete** | [TECH_STACK.md](./TECH_STACK.md), [MVP_SCOPE.md](./MVP_SCOPE.md), [DECISIONS.md](./DECISIONS.md), [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) |
| **Phase 3 (Day 1)** | Architecture Freeze (`D-01`, `D-02`, `D-07`), Rust Workspace & `crates/protocol` | **Complete (`Verified`)** | [Cargo.toml](./Cargo.toml), [crates/protocol](./crates/protocol/Cargo.toml), [protocol_tests.rs](./crates/protocol/tests/protocol_tests.rs) (`10/10` passed) |
| **Phase 4 (Day 2)** | Cryptography (`crypto`), Transport & SSRF (`network`), Relay Engine (`relay`), Client & E2E (`client`) | **Complete (`Verified`)** | `crates/crypto`, `crates/network`, `crates/relay`, `crates/client` (`29/29` Day 2 baseline passed) |
| **Phase 5 (Day 3)** | Link Rekeying (`D-09`), Hardening, Standalone CLIs (`crates/cli`), 5-Process Demo (`demo/`), Classified Security Review & Release Docs | **Complete (`Verified`)** | [crates/cli](./crates/cli/Cargo.toml), [demo/README.md](./demo/README.md), [SECURITY_REVIEW.md](./SECURITY_REVIEW.md), `40/40` workspace tests + `clippy -D warnings` + live 10-case PS demo + multi-process log proof passed |
| **Phase 6–12** | Coordinator Registry, Docker Containers, Kubernetes, Prometheus Metrics, External Audit & LLM Integration | **Deferred Beyond v0.1** | Docker Desktop daemon not running (`DEFERRED`); Kubernetes, Prometheus, and LLM integration excluded from Day 3 release scope |

---

## Capability Implementation Breakdown

- **Implemented & Verified (`v0.1` Days 1–3):**
  - `private-relay-protocol` (`10/10` tests): bounded `600B` link frames (`D-02`), link rekey control framing (`D-09`), `9B` cells, `<= 64 KiB` chunking/reassembly (`D-01`), `15B` hop AAD (`D-07`).
  - `private-relay-crypto` (`6/6` tests): `Noise_IK` + synchronized link rekeying (`snow::TransportState`), `Noise_NK` hops + `D-08` exporter, `ChaCha20-Poly1305` FIFO replay protection, `StaticKeypair` consistency validation & `ZeroizeOnDrop`.
  - `private-relay-network` (`5/5` tests): TOML `RelayConfig` + `ClientConfigFile` schema/role/loop checks, hardened IPv4/IPv6 `DestinationPolicy`, async `LinkReader`/`LinkWriter` supporting partial TCP & rekeys.
  - `private-relay-relay` (`6/6` tests): parameterized `Entry`/`Middle`/`Exit`, `max_concurrent_connections` semaphore + permit release, `max_concurrent_circuits`, Entry per-IP cap, cancellation-safe extension, DNS-once timeout-guarded `SocketAddr` connect (`SEC-201`), PII-free `tracing`.
  - `private-relay-client` (`10/10` tests): 3-hop telescopic client (`RelayClient`), `64 KiB` / SSRF / slowloris / crash / tamper / log-redaction / redirect / multi-rekey E2E coverage.
  - `private-relay-cli` (`3/3` tests) & [demo/](./demo/README.md): standalone OS executables `relay-entry`, `relay-middle`, `relay-exit`, `relay-client`, `demo-dest`, and `relay-keygen` with distinct-PID process log verification (`STATUS=READY`, `"relay node started"`, `"circuit hop established"`, zero secret/IP/payload leaks) and Windows PowerShell automation (`demo/start-demo.ps1`, `demo/run-demo.ps1`, `demo/stop-demo.ps1`).
- **Partially Implemented / Platform-Scoped:** Multi-process Windows PowerShell demo verified; POSIX Bash launch scripts not added (`PowerShell` + pure-Rust cross-platform binaries exist). Automatic link rekey tested cleanly with small byte/time thresholds (`3600s` / `1 GiB` defaults configured in code, multi-hour soak not run).
- **Deferred Beyond `v0.1` / Requires External Audit:** Docker containers (`dockerDesktopLinuxEngine` offline on host), Coordinator signed directory (`Phase 5`), Kubernetes/Prometheus observability, LLM assistant, `cargo-audit` CVE scanning, and external cryptographic/security audit ([SECURITY_REVIEW.md](./SECURITY_REVIEW.md)).
