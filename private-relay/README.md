# Private-Relay Protocol

A research-oriented, 3-hop privacy-preserving relay overlay (`Client → Entry → Middle → Exit → Destination`) engineered in Rust with Noise Protocol handshakes and per-hop authenticated encryption.

> **Current Phase:** **Day 5 Complete — `Private-Relay v0.1` Multi-Process & 5-Container Docker Stack Verified (`40/40` tests + Docker Compose E2E)**  
> **Code Status:** Standalone CLIs (`relay-entry`, `relay-middle`, `relay-exit`, `relay-client`, `demo-dest`, `relay-keygen`), hardened multi-stage [Dockerfile](./Dockerfile) & [docker-compose.yml](./docker-compose.yml), coordinated `Noise_IK` link rekeying (`D-09`), hardened SSRF (`D4-01`), and security/audit reports ([SECURITY_REVIEW.md](./SECURITY_REVIEW.md), [DAY4_VERIFICATION_REPORT.md](./DAY4_VERIFICATION_REPORT.md), [docs/DAY_5_DOCKER_REPORT.md](./docs/DAY_5_DOCKER_REPORT.md)) complete. **Research prototype only — not externally audited or production-ready.**

---

## Quick Start (Docker Containerized 5-Node Topology & Windows Demo)

Run the isolated 5-container stack (`demo-dest`, `relay-exit`, `relay-middle`, `relay-entry`, one-shot `relay-client`):

```powershell
cd private-relay
.\demo\run-docker-demo.ps1
```

Or run bare-metal Windows OS processes directly:

```powershell
cd private-relay
.\demo\run-demo.ps1 -AutoStartStop
```

See [demo/README.md](./demo/README.md) for manual Docker Compose commands, manual 5-terminal commands, key generation (`relay-keygen`), troubleshooting, and workspace verification (`cargo test --offline --workspace`).

---

## Project Index

### Protocol, Threat Model & Architecture (`Phase 1` & Security Review)
- [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md) — Wire framing (`600B` outer Noise link frames, `9B` cell headers), telescopic `Noise_NK` circuits, `ChaCha20-Poly1305` layering, replay rules, and limitations.
- [SECURITY_DESIGN.md](./SECURITY_DESIGN.md) — Primitive selection, `HKDF-SHA256` directional key separation, link rekeying (`D-09`), deterministic nonces, SSRF/DNS bounds, and log redaction rules.
- [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) — Classified Day 3 internal security review (`Critical`/`High`/`Medium`/`Low`/`Informational`, 16-point inspection, limitations, and external audit gates).
- [DAY4_VERIFICATION_REPORT.md](./DAY4_VERIFICATION_REPORT.md) — Independent Day 4 engineering audit report (protocol trace, `D4-01`/`D4-02` remediations, live demo PID leak check, & offline dependency/license verification).
- [docs/DAY_5_DOCKER_REPORT.md](./docs/DAY_5_DOCKER_REPORT.md) — Day 5 multi-stage Docker build, Compose topology, health checks, security audit, and 12-scenario containerized E2E results.
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Analysis of 9 threat categories + verification tests.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — Trust boundaries, RAM state tables, and 6 Mermaid diagrams (architecture, trust zones, circuit build, request flow, response flow, failure teardown).

### Operational Guides, Crates & Continuity
- [demo/README.md](./demo/README.md) — Full Windows PowerShell multi-process setup, run, log-proof verification, and teardown instructions.
- [TECH_STACK.md](./TECH_STACK.md) & [docs/TECH_DECISIONS.md](./docs/TECH_DECISIONS.md) — Stack evaluation and anti-overengineering guardrails.
- [MVP_SCOPE.md](./MVP_SCOPE.md) — `FR-01`..`FR-08`, hard memory/circuit limits, targets vs. claims, and privacy boundaries.
- [PROJECT_STATUS.md](./PROJECT_STATUS.md) — Current phase and verified/partial/deferred breakdown.
- [DECISIONS.md](./DECISIONS.md) — Architectural decision log (`D-01`..`D-09`).
- [ROADMAP.md](./ROADMAP.md) — Phase 1–12 roadmap and capability status matrix.
- [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) — Open limitations, correlation risks, and SSRF/TOCTOU/audit notes.
- [TEST_RESULTS.md](./TEST_RESULTS.md) — Verified environment checks, `40/40` workspace test results, and live 5-process demo run metrics.
- [CHANGELOG.md](./CHANGELOG.md) — Chronological record of specifications and releases.
