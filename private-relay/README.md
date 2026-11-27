# Private-Relay Protocol

A research-oriented, 3-hop privacy-preserving relay overlay (`Client → Entry → Middle → Exit → Destination`) engineered in Rust with Noise Protocol handshakes and per-hop authenticated encryption.

> **Current Phase:** **Day 3 Complete — `Private-Relay v0.1` Prototype Verified (`39/39` workspace tests passing + 5-process Windows local demo verified)**  
> **Code Status:** Standalone CLIs (`relay-entry`, `relay-middle`, `relay-exit`, `relay-client`, `demo-dest`, `relay-keygen`), coordinated `Noise_IK` link rekeying (`D-09`), hardened TOML/SSRF/connection controls, and internal security review (`SECURITY_REVIEW.md`) complete. **Research prototype only — not externally audited or production-ready.**

---

## Quick Start (Windows Multi-Process Local Demo)

Run all 5 independent OS processes (`demo-dest`, `relay-exit`, `relay-middle`, `relay-entry`, `relay-client`) locally via PowerShell:

```powershell
cd private-relay
.\demo\run-demo.ps1 -AutoStartStop
```

See [demo/README.md](./demo/README.md) for exact manual 5-terminal commands, key generation (`relay-keygen`), troubleshooting, and workspace verification (`cargo test --offline --workspace`).

---

## Project Index

### Protocol, Threat Model & Architecture (`Phase 1` & Security Review)
- [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md) — Wire framing (`600B` outer Noise link frames, `9B` cell headers), telescopic `Noise_NK` circuits, `ChaCha20-Poly1305` layering, replay rules, and limitations.
- [SECURITY_DESIGN.md](./SECURITY_DESIGN.md) — Primitive selection, `HKDF-SHA256` directional key separation, link rekeying (`D-09`), deterministic nonces, SSRF/DNS bounds, and log redaction rules.
- [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) — Focused 16-point Day 3 internal security review (verified properties, local-only scope, unverified assumptions, and external audit gates).
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Analysis of 9 threat categories + verification tests.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — Trust boundaries, RAM state tables, and 6 Mermaid diagrams (architecture, trust zones, circuit build, request flow, response flow, failure teardown).

### Operational Guides, Crates & Continuity
- [demo/README.md](./demo/README.md) — Full Windows PowerShell multi-process setup, run, and teardown instructions.
- [TECH_STACK.md](./TECH_STACK.md) & [docs/TECH_DECISIONS.md](./docs/TECH_DECISIONS.md) — Stack evaluation and anti-overengineering guardrails.
- [MVP_SCOPE.md](./MVP_SCOPE.md) — `FR-01`..`FR-08`, hard memory/circuit limits, targets vs. claims, and privacy boundaries.
- [PROJECT_STATUS.md](./PROJECT_STATUS.md) — Current phase and verified/partial/deferred breakdown.
- [DECISIONS.md](./DECISIONS.md) — Architectural decision log (`D-01`..`D-09`).
- [ROADMAP.md](./ROADMAP.md) — Phase 1–12 roadmap and capability status matrix.
- [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) — Open limitations, correlation risks, and SSRF/TOCTOU/audit notes.
- [TEST_RESULTS.md](./TEST_RESULTS.md) — Verified environment checks, `39/39` workspace test results, and live 5-process demo run metrics.
- [CHANGELOG.md](./CHANGELOG.md) — Chronological record of specifications and releases.
