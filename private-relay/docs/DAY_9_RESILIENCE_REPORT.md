# DAY 9 — FAILURE INJECTION, RESILIENCE & CONCURRENCY REPORT

**Date:** 2026-11-28  
**Engineer:** Principal Distributed Systems & Reliability Engineer  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Cluster Environment:** `kind` `v1.32.2` + Calico `v3.29.1` & Rust Workspace (`resilience_tests.rs`)  

---

## 1. Executive Summary

Day 9 validated Private Relay v0.1 under live Kubernetes component restarts, fail-closed relay outages, mid-flight `SIGTERM` termination, malformed destination responses, repeated failures, and bounded concurrency bursts (`1`, `5`, `10`, `25` simultaneous clients).

In-flight circuits terminate cleanly rather than surviving relay Pod deletion (since circuit keys and `CircuitTable` state live strictly in ephemeral relay RAM by security design), and every component recovered automatically inside Kubernetes (`4.3s–5.2s`), passing new 3-hop requests (`17ms–28ms`) with **zero Pod crash loops** and **zero memory leaks**.

---

## 2. Live Kubernetes Component Restart & Recovery Results (`Section 9.1`)

Measured by deleting each active Pod (`--grace-period=5`), timing `kubectl wait --for=condition=available`, and executing a fresh 3-hop client request (`GET /health`):

| Target Component | Failure Injection | Recovery Time (`Available`) | Post-Recovery Request | Client Latency |
|---|---|---|---|---|
| **Entry (`private-relay-entry`)** | `kubectl delete pod` | `4712 ms` | `HTTP/1.1 200 OK` (new circuit) | `28 ms` |
| **Middle (`private-relay-middle`)** | `kubectl delete pod` | `4354 ms` | `HTTP/1.1 200 OK` (new circuit) | `27 ms` |
| **Exit (`private-relay-exit`)** | `kubectl delete pod` | `4308 ms` | `HTTP/1.1 200 OK` (new circuit) | `24 ms` |
| **Destination (`private-relay-destination`)** | `kubectl delete pod` | `4411 ms` | `HTTP/1.1 200 OK` (new circuit) | `17 ms` |

**Honest Survival Boundary:** Existing circuits **do not** survive a relay restart because ephemeral `Noise_NK` session keys live strictly in Pod RAM (`zeroize`d on drop). Client-initiated retries establish fresh circuits cleanly after Deployment readiness (`--probe-noise`) passes.

---

## 3. Failure Injection Scenarios (`Section 9.2`)

| # | Scenario | Injection Method | Expected Behavior | Actual Observed Behavior & Evidence |
|---|---|---|---|---|
| 1 | Destination unavailable | Rust `resilience_tests.rs` & dead target port | `ConnectFailed` error without relay panic | `Circuit` returns error cleanly; sibling requests unaffected |
| 2 | Malformed destination bytes | Binary `0xFF 0x00 0xFE 0x7F 0x01` payload (`resilience_tests.rs`) | Returned verbatim or failed cleanly; zero crash | Returned `5B` safely; circuit reused successfully afterward |
| 3 | Slow destination (`>5s`) | Live K8s `/slow` (`5500ms` delay vs `5000ms` Exit cap) | `RequestErrorCode::Timeout` enforced at Exit | `REMOTE_ERROR(Timeout: destination I/O timed out)` in `5012 ms` |
| 4 | Middle relay unavailable | Live K8s `kubectl scale middle --replicas=0` | Client fails closed (never bypasses Middle) | Failed (`HandshakeTimeout`), restored in `5184 ms` -> `200 OK` (`25 ms`) |
| 5 | Exit relay unavailable | Live K8s Pod deletion & Rust test | Fails closed -> recovers on Pod ready | Recovered in `4308 ms` -> next circuit `200 OK` (`24 ms`) |
| 6 | Entry relay unavailable | Live K8s Pod deletion & Rust test | Connection refused/timeout -> recovers | Recovered in `4712 ms` -> next circuit `200 OK` (`28 ms`) |
| 7 | Client disconnects mid-request | Abrupt `Circuit` / socket drop | Relay detects EOF/cancellation & frees slots | `active_circuits` returns cleanly to `0` (`engine.rs` `CircuitSlotGuard`) |
| 8 | Relay `SIGTERM` mid-request | Live K8s `delete pod middle` during active `/slow` | Graceful drain delivers `DESTROY(Normal)` | Client received `CIRCUIT_DESTROYED(Normal)` (`491 ms`); new circuit `27 ms` |
| 9 | Repeated request failures | 5x `169.254.169.254:80` SSRF blocks (`resilience_tests.rs`) | Policy blocks cleanly; circuit remains healthy | 5/5 `PolicyDenied`, followed immediately by `200 OK` on same circuit |
| 10 | Repeated connection attempts | 54 sequential/concurrent circuits in K8s (`131` total scraped) | Clean allocation/destruction without exhaustion | `sum(active_circuits) == 0`, `circuits_created == 131 == circuits_destroyed` |

### Code Reliability Fix Discovered During Testing
- **Shutdown Drain Race (`crates/relay/src/engine.rs`):** High-concurrency stress runs exposed a scheduling race in `spawn_inbound_link_loop()` where `notify_routes_disconnected(&routes)` could inject `DestroyReason::PeerDisconnected` into active circuit tasks before their `shutdown_rx.changed()` handler emitted `DestroyReason::Normal`. Fixed by checking `*shutdown_r.borrow()` at loop entry/exit, skipping fake `PeerDisconnected` during graceful shutdown, and checking `*shutdown_rx.borrow()` at the top of circuit loops. Verified both by `shutdown_drains_active_circuits_and_delivers_destroy_cleanly` and live K8s `CIRCUIT_DESTROYED(Normal)` observation.

---

## 4. Concurrency & Resource Consumption Measurements (`Section 9.3–9.4`)

### A. Live Kubernetes Cluster Concurrency Ramp (`pod/private-relay-test-client`)
All clients executed from the **same** single client Pod IP against `Entry` (`max_circuits_per_peer_ip = 16`):

| Concurrency | Elapsed (`ms`) | Succeeded | Rejected / Rate-Limited | Notes |
|---|---|---|---|---|
| `1` | `678 ms` | `1` | `0` | Baseline single Pod exec spawn |
| `5` | `655 ms` | `5` | `0` | Within per-IP cap (`16`) |
| `10` | `724 ms` | `10` | `0` | Within per-IP cap (`16`) |
| `25` | `896 ms` | `17` | `8` | Single-IP DoS cap (`max_circuits_per_peer_ip=16`) logged 8 `[WARN] circuit rejected due to resource capacity limit` on Entry; 0 Pod crashes or restarts |

### B. Rust Multi-Client Harness (`resilience_concurrency_ramp_1_5_10_25_and_state_cleanup`, `max_circuits_per_peer_ip=64`)
| Concurrency | Elapsed | Succeeded | Failed | Throughput (`req/s`) | Post-Test Active Circuits |
|---|---|---|---|---|---|
| `1` | `109.10 ms` | `1` | `0` | `9.2 req/s` | `0` |
| `5` | `355.78 ms` | `5` | `0` | `14.1 req/s` | `0` |
| `10` | `714.96 ms` | `10` | `0` | `14.0 req/s` | `0` |
| `25` | `1.786 s` | `25` | `0` | `14.0 req/s` | `0` (Entry, Middle, Exit) |

### C. Pod Cgroup v2 Memory Stability (Pre-Load vs Post-Load)

| Workload | Pre-Load Memory | Post-Load Memory | Restarts |
|---|---|---|---|
| `private-relay-entry` | `2.61 MiB` | `2.61 MiB` | `0` |
| `private-relay-middle` | `2.88 MiB` | `2.11 MiB` | `0` |
| `private-relay-exit` | `2.23 MiB` | `2.89 MiB` | `0` |
| `private-relay-destination` | `3.77 MiB` | `2.32 MiB` | `0` |
| `prometheus` | `25.52 MiB` | `27.18 MiB` | `0` |
| `grafana` | `48.45 MiB` | `48.60 MiB` | `0` |
| Kind Node (`private-relay-control-plane`) | — | `1.349 GiB / 15.26 GiB (8.84%)` | — |

---

## 5. Remaining Gaps & Unverified Scope

- Multi-Pod distinct-IP `25+` client Pod scaling in Kubernetes was not run separately; `25` parallel clients from 1 Pod IP verified the single-IP DoS limit (`max_circuits_per_peer_ip=16`), while full `25/25` throughput was verified in `resilience_tests.rs`.
- Multi-hour sustained WAN soak tests remain deferred post-`v0.1`.
