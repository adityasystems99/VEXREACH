# Private-Relay Protocol

A research-oriented, 3-hop privacy-preserving relay overlay (`Client → Entry → Middle → Exit → Destination`) engineered in Rust with Noise Protocol handshakes and per-hop authenticated encryption.

> **Current Phase:** **Days 8–10 Complete — Live `kind` (`v1.32.2`) + Calico (`v3.29.1`) Kubernetes Deployment, Failure-Injection Resilience, & Privacy-Preserving Prometheus/Grafana Observability (`54/54` Rust tests, `12/12` Docker Compose E2E, `12/12` K8s Multi-Hop Traffic, `15/15` Live Calico NetworkPolicy Probes)**  
> **Code Status:** Standalone CLIs (`relay-entry`, `relay-middle`, `relay-exit` with `--metrics-addr`, `relay-client` with `--probe`/`--probe-noise`/`--probe-http`, `demo-dest`, `relay-keygen` with `--split-dirs`/`--key-file-path`), hardened multi-stage [Dockerfile](./Dockerfile) & [docker-compose.yml](./docker-compose.yml), hardened Kubernetes Kustomize + Prometheus/Grafana manifests ([k8s/](./k8s/README.md)), coordinated `Noise_IK` link rekeying (`D-09`), Day 7 security audit (`SEC-701`–`SEC-709`), live Calico `NetworkPolicy` enforcement, resilience suite, and Days 8–10 verification reports ([docs/DAY_8_DEPLOYMENT_REPORT.md](./docs/DAY_8_DEPLOYMENT_REPORT.md), [docs/DAY_9_RESILIENCE_REPORT.md](./docs/DAY_9_RESILIENCE_REPORT.md), [docs/DAY_10_OBSERVABILITY_REPORT.md](./docs/DAY_10_OBSERVABILITY_REPORT.md), [docs/DAY_8_10_INTEGRATED_REPORT.md](./docs/DAY_8_10_INTEGRATED_REPORT.md)) complete. **Research prototype only — not externally audited or production-ready.**

---

## Quick Start (Docker Containerized 5-Node Topology, Kubernetes & Windows Demo)

Run the isolated 5-container Docker Compose stack (`demo-dest`, `relay-exit`, `relay-middle`, `relay-entry`, one-shot `relay-client`):

```powershell
cd private-relay
.\demo\run-docker-demo.ps1
```

Or run bare-metal Windows OS processes directly:

```powershell
cd private-relay
.\demo\run-demo.ps1 -AutoStartStop
```

For Kubernetes Kustomize deployment (`k8s/`, offline Kustomize verified; live cluster required for deployment), see [k8s/README.md](./k8s/README.md).

See [demo/README.md](./demo/README.md) for manual Docker Compose commands, manual 5-terminal commands, key generation (`relay-keygen`), troubleshooting, and workspace verification (`cargo test --offline --workspace`).

---

## Project Index

### Protocol, Threat Model & Architecture (`Phase 1` & Security Review)
- [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md) — Wire framing (`600B` outer Noise link frames, `9B` cell headers), telescopic `Noise_NK` circuits, `ChaCha20-Poly1305` layering, replay rules, and limitations.
- [SECURITY_DESIGN.md](./SECURITY_DESIGN.md) — Primitive selection, `HKDF-SHA256` directional key separation, link rekeying (`D-09`), deterministic nonces, SSRF/DNS bounds, and log redaction rules.
- [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) — Classified Day 3 internal security review (`Critical`/`High`/`Medium`/`Low`/`Informational`, 16-point inspection, limitations, and external audit gates).
- [DAY4_VERIFICATION_REPORT.md](./DAY4_VERIFICATION_REPORT.md) — Independent Day 4 engineering audit report (protocol trace, `D4-01`/`D4-02` remediations, live demo PID leak check, & offline dependency/license verification).
- [docs/DAY_5_DOCKER_REPORT.md](./docs/DAY_5_DOCKER_REPORT.md) — Day 5 multi-stage Docker build, Compose topology, health checks, security audit, and 12-scenario containerized E2E results.
- [docs/DAY_6_KUBERNETES_REPORT.md](./docs/DAY_6_KUBERNETES_REPORT.md) — Day 6 hardened Kubernetes manifests, Secret-file separation, real `--probe-noise` / `--probe-http` checks, and Kustomize baseline.
- [docs/DAY_7_SECURITY_AUDIT.md](./docs/DAY_7_SECURITY_AUDIT.md) — Day 7 independent security & reliability audit (`SEC-701`–`SEC-709`).
- [docs/DAY_8_DEPLOYMENT_REPORT.md](./docs/DAY_8_DEPLOYMENT_REPORT.md) — Day 8 live `kind` + Calico Kubernetes deployment, `12/12` in-cluster traffic tests, & `15/15` live `NetworkPolicy` enforcement proofs.
- [docs/DAY_9_RESILIENCE_REPORT.md](./docs/DAY_9_RESILIENCE_REPORT.md) — Day 9 live relay restart recovery, fail-closed checks, mid-flight `SIGTERM` drain, `1..25` concurrency, & Pod cgroup memory stats.
- [docs/DAY_10_OBSERVABILITY_REPORT.md](./docs/DAY_10_OBSERVABILITY_REPORT.md) — Day 10 zero-PII Prometheus exporter, scrape target health, live TSDB deltas, & 10-panel Grafana verification.
- [docs/DAY_8_10_INTEGRATED_REPORT.md](./docs/DAY_8_10_INTEGRATED_REPORT.md) — Consolidated Days 8–10 engineering sprint summary.
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
- [TEST_RESULTS.md](./TEST_RESULTS.md) — Verified environment checks, `54/54` workspace test results, `12/12` Docker Compose E2E, live `kind`/Calico/Prometheus/Grafana checks, and OS demo metrics.
- [CHANGELOG.md](./CHANGELOG.md) — Chronological record of specifications and releases.
