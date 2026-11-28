# DAY 10 — PRIVACY-PRESERVING OBSERVABILITY, PROMETHEUS & GRAFANA REPORT

**Date:** 2026-11-28  
**Engineer:** Principal Observability & Security Architect  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Cluster Environment:** `kind` `v1.32.2` + Calico `v3.29.1` (`Prometheus v2.53.0` + `Grafana 11.1.0`)  

---

## 1. Executive Summary

Day 10 implemented a zero-dependency, privacy-preserving Prometheus exposition endpoint directly in the Private Relay runtime (`crates/network/src/metrics.rs`, `crates/relay/src/engine.rs`, `--metrics-addr` CLI flag), isolated Kubernetes scrape Services + Calico `NetworkPolicy` locks (`k8s/observability-prometheus.yaml`), and a provisioned 10-panel Grafana dashboard (`k8s/observability-grafana.yaml`).

Live cluster verification confirmed:
- All **3 relay scrape targets** (`private-relay-entry`, `private-relay-middle`, `private-relay-exit`) are `up` (`5.78ms–6.09ms` scrape duration).
- Real multi-hop traffic produced **measured live deltas** inside Prometheus TSDB (`requests_total: 41 -> 44`, `ssrf_denials_total: 1 -> 2`, `bytes_sent_total: 393600 -> 422400`).
- **Prometheus Label Privacy Audit** confirmed strictly bounded labels (`__name__, instance, job, le, node, role`) — zero IPs, hostnames, URLs, `CircuitId`s, `RequestId`s, or payloads.
- **Grafana `11.1.0`** (`database=ok`) connected to `Prometheus` (`uid=prometheus`), executed live datasource proxy queries (`sum(private_relay_up) = 3`), and loaded the 10-panel dashboard (`uid=private-relay-v01`).

---

## 2. Prometheus Exporter Implementation & Privacy Contract

- **Rust Implementation:**
  - `RelayMetrics` (`crates/network/src/metrics.rs`) renders Prometheus text format `0.0.4`.
  - Bounded `/metrics` HTTP endpoint (`2s` request timeout, `1024B` read limit, `/healthz` health response, `404`/`405` on unknown/non-GET requests) exposed via `--metrics-addr <IP:PORT>` on `relay-entry`, `relay-middle`, and `relay-exit` ([crates/cli/src/lib.rs](../crates/cli/src/lib.rs)).
  - **Strict Cardinality / Zero-PII Guarantee:** Every metric carries strictly `role ∈ {entry, middle, exit}`, sanitized `node`, and bounded histogram `le` bucket bounds (`0.005s..5s`, `+Inf`). Never emits IPs, URLs, hostnames, IDs, payloads, or key material.

### Metrics Actually Collected & Verified Live in Kubernetes Prometheus TSDB

| Metric Family | Live Value Observed (`sum`) | Meaning |
|---|---|---|
| `private_relay_up` | `3` | All 3 relays healthy (`1` each) |
| `private_relay_active_circuits` | `0` | Active circuits returned to `0` after tests |
| `private_relay_circuits_created_total` | `131` | Total circuit hops created across Entry/Middle/Exit |
| `private_relay_circuits_destroyed_total` | `131` | Equal to created -> zero leaked circuits |
| `private_relay_hop_handshakes_total` | `217` | Verified `Noise_NK` `Created` completions |
| `private_relay_connections_accepted_total` | `167` | Inbound `Noise_IK` links accepted |
| `private_relay_bytes_received_total` | `449400` (`749` frames) | Uniform `600B` link frames received |
| `private_relay_bytes_sent_total` | `422400` (`704` frames) | Uniform `600B` link frames transmitted |
| `private_relay_cells_processed_total` | `749` | Onion cells peeled/forwarded |
| `private_relay_requests_total` | `44` | Destination requests executed by Exit |
| `private_relay_requests_success_total` | `41` | Successful Exit responses |
| `private_relay_requests_failed_total` | `2` | Failed requests |
| `private_relay_ssrf_denials_total` | `2` | Exit SSRF blocks (`PolicyDenied`) |
| `private_relay_request_duration_seconds_count` | `43` | Observed Exit latency histogram count |
| `private_relay_request_duration_seconds_sum` | `0.391054` s | Cumulative Exit destination duration (`~9.1 ms` avg) |

*(Additional instrumented counters verified in automated tests: `private_relay_timeouts_total`, `private_relay_payload_too_large_total`, `private_relay_protocol_violations_total`, `private_relay_destination_connect_failures_total`, `private_relay_connections_rejected_total`, `private_relay_hop_handshake_failures_total`, `private_relay_link_rekeys_total`, `private_relay_process_uptime_seconds`, `private_relay_max_circuits`, `private_relay_max_connections`.)*

---

## 3. Kubernetes Scrape Discovery & Network Isolation

- **Services:** Dedicated ClusterIP Services `private-relay-entry-metrics:9091`, `private-relay-middle-metrics:9091`, and `private-relay-exit-metrics:9091` prevent exposing metrics ports on the primary relay data services (`9101`/`9102`/`9103`).
- **Calico `NetworkPolicy` Locks (`k8s/network-policy.yaml`):**
  - `entry-relay-policy`, `middle-relay-policy`, `exit-relay-policy` permit port `9091` ingress **strictly** from `app.kubernetes.io/component: prometheus` (confirmed earlier when `client -> entry-metrics:9091` was `DENIED`).
  - `prometheus-policy` permits ingress from `grafana:3000` -> `9090` and egress only to relay metrics `9091` (+ CoreDNS).
  - `grafana-policy` permits egress only to `prometheus:9090` (+ CoreDNS).

---

## 4. Grafana Provisioning & Dashboard Verification

- **Deployment & PSS Restricted Hardening:** `grafana/grafana:11.1.0` (`runAsUser: 472`, `readOnlyRootFilesystem: true`, `emptyDir` mounts for `/var/lib/grafana` and `/tmp`, provisioned files under `/etc/grafana/provisioning/*` and `/etc/grafana/dashboards`).
- **10 Dashboard Panels Verified (`uid: private-relay-v01`):**
  1. Relay Health (Up)
  2. Active Circuits
  3. Rejected SSRF Requests
  4. Relay Restarts & Uptime (seconds)
  5. Request Rate (req/s)
  6. Error Rate (err/s)
  7. Timeout Rate (timeouts/s)
  8. Traffic Volume (Bytes/sec)
  9. Resource Consumption (Links & Circuits)
  10. Exit Request Latency (p50 & p95 seconds histogram quantile)
- **Live Verification Evidence:**
  - `/api/health`: `database=ok`, `version=11.1.0`.
  - `/api/datasources`: `Prometheus (prometheus uid=prometheus)`.
  - `/api/datasources/proxy/uid/prometheus/api/v1/query?query=sum(private_relay_up)` -> `3`.
  - `/api/dashboards/uid/private-relay-v01` -> `title='Private Relay v0.1 - Privacy-Preserving Operations'`, `panels=10`.
