# CONSOLIDATED ENGINEERING REPORT — DAYS 8, 9 & 10

**Date:** 2026-11-28  
**Project:** Private Relay v0.1 (`adityasystems99/VEXREACH`, `private-relay/`, branch `master`)  
**Security Audit Baseline:** `41280d75644ff42726de3172a751eede0927f798` (Day 7)  
**Classification:** Unaudited Research Prototype — Live Kubernetes, Resilience & Observability Verification  

---

## 1. Consolidated Milestone Matrix

| Milestone | Scope | Verification Status | Primary Evidence |
|---|---|---|---|
| **Day 8** | Live `kind` (`v1.32.2`) + Calico (`v3.29.1`) deployment, secret separation, 12-case K8s E2E traffic, 15-case CNI `NetworkPolicy` enforcement | **VERIFIED** | [DAY_8_DEPLOYMENT_REPORT.md](./DAY_8_DEPLOYMENT_REPORT.md) |
| **Day 9** | Entry/Middle/Exit/Dest Pod restarts, `replicas=0` fail-closed outage, mid-flight `SIGTERM` graceful drain, 1/5/10/25 concurrency & cgroup v2 memory | **VERIFIED** | [DAY_9_RESILIENCE_REPORT.md](./DAY_9_RESILIENCE_REPORT.md) |
| **Day 10** | Native Prometheus exporter (`RelayMetrics`, `--metrics-addr`), dedicated scrape services, live TSDB deltas, privacy label audit, 10-panel Grafana dashboard | **VERIFIED** | [DAY_10_OBSERVABILITY_REPORT.md](./DAY_10_OBSERVABILITY_REPORT.md) |
| **Workspace & Containers** | `cargo fmt --check`, `cargo clippy -D warnings`, **54/54** Rust tests, rebuilt `private-relay:v0.1` + **12/12** Docker Compose E2E | **VERIFIED** | [TEST_RESULTS.md](../TEST_RESULTS.md) |
| **Static CVE / Fuzzing / Prod Audit** | `cargo-audit` / `cargo-deny` (absent offline), `cargo-fuzz`, third-party cryptographic audit | **NOT VERIFIED** | Tracked in [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) (`KI-09`) |

---

## 2. Architecture & Security Controls Proven in Live Execution

1. **Zero Secret Material in ConfigMaps, Env, or Client:** `private-relay-keygen` writes private keys strictly to per-relay Secrets mounted under `/run/secrets/private_key_hex` without `subPath`, running under PSS `restricted` (`UID 10001`, read-only rootfs).
2. **Real Calico L3/L4 `NetworkPolicy` Enforcement:** Verified live that Client -> Entry (`9101`), Entry -> Middle (`9102`), Middle -> Exit (`9103`), Exit -> Destination (`9000`), and Prometheus -> `*-metrics:9091` are `ALLOWED`, while all bypass paths, client-to-metrics probes, reverse directions, destination egress, and external `1.1.1.1:80` egress are `DENIED`.
3. **Graceful Drain & DoS Bounds:** Mid-flight `SIGTERM` on Middle returned clean `CIRCUIT_DESTROYED(Normal)` (`491ms`), and `25` simultaneous client requests from one Pod IP hit Entry's `max_circuits_per_peer_ip=16` cap cleanly (`17` ok, `8` rejected cleanly with `[WARN]`, `0` restarts).
4. **Zero-PII Telemetry:** Prometheus exposes strictly low-cardinality bounded labels (`role`, `node`, histogram `le`) and recorded live request/SSRF/byte/latency deltas across real multi-hop cluster traffic.

---

## 3. Remaining Prototype Limits

- **Single-Replica Relay Constraint (`KI-10`):** Horizontal scaling requires Coordinator discovery and per-Pod identities (`Phase 11+`).
- **Dual-Ended Passive Traffic Correlation (`KI-01`):** Constant `600B` Noise framing prevents single-cell size leaks, not global flow/timing correlation.
- **No Claim of Production Security (`KI-09`):** Remains an engineering research prototype until formal external cryptographic audit, fuzzing, and CVE scanning complete.
