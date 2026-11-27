# Day 5 Docker Containerization Report — Private-Relay (`v0.1`)

> **Date:** `2026-11-27`  
> **Status:** **COMPLETE & VERIFIED — Hardened 5-Container Stack Built & Tested End-to-End**  
> **Starting Verified Baseline:** `2c3951465617b2efdbb4ec9ceb228a72125a0237` (Day 4 `master` / `origin/master`; Day 5 blocker note superseded at `02f8724`)  
> **Scope Guardrail:** Preserved Noise/AEAD cryptographic protocol invariants (`D-01`–`D-09`) and Exit SSRF protections (`D4-01`) cleanly inside `private-relay/` without adding external crates or starting Kubernetes, Prometheus, or LLM integrations.

---

## 1. Docker Architecture & Container Names

The Compose topology isolates all traffic on an internal Docker bridge network (`private-relay_relay_net`, `driver: bridge`, `internal: true`) with zero published host ports:

```text
relay-keygen (init) ──▶ [exit_cfg / middle_cfg / entry_cfg / client_cfg (0600, UID 10001)]
                                  │
private-relay-client ──▶ private-relay-entry (:9101) ──▶ private-relay-middle (:9102) ──▶ private-relay-exit (:9103) ──▶ private-relay-dest (:9000)
```

| Service | Container Name | Role & Network Endpoint | Config Volume / Mount |
| :--- | :--- | :--- | :--- |
| `relay-keygen` | `private-relay-keygen` | Init generator creating ephemeral keys + per-node TOMLs (`Exited 0`) | Writes `entry_cfg`, `middle_cfg`, `exit_cfg`, `client_cfg` |
| `demo-dest` | `private-relay-dest` | Controlled test HTTP/TCP server (`demo-dest:9000`, bound `0.0.0.0:9000`) | Image `/app/destination.toml` (`0444`, static non-secret) |
| `relay-exit` | `private-relay-exit` | Hop 3 Exit (`relay-exit:9103`, bound `0.0.0.0:9103`) | `exit_cfg:/cfg:ro` (`allow_loopback_for_test=false`, `allow_private_targets_for_test=true`, `allowed_targets=["demo-dest:9000"]`) |
| `relay-middle` | `private-relay-middle` | Hop 2 Middle (`relay-middle:9102`, bound `0.0.0.0:9102`) | `middle_cfg:/cfg:ro` |
| `relay-entry` | `private-relay-entry` | Hop 1 Entry (`relay-entry:9101`, bound `0.0.0.0:9101`) | `entry_cfg:/cfg:ro` |
| `relay-client` | `private-relay-client` (`profile: client`) | Ephemeral one-shot 3-hop client (`private-relay-relay-client-run-*`) | `client_cfg:/cfg:ro` (public descriptors only; zero private keys) |

---

## 2. Multi-Stage Build Results ([Dockerfile](../Dockerfile))

- **Builder Stage:** Pinned `rust:1.93.1-slim-bookworm` matching verified host `rustc 1.93.1`. Uses manifest-only dependency caching (`Cargo.toml` + `Cargo.lock` + dummy crate stubs -> `32.03s` release deps compile), builds real `crates/` with `cargo build --release --locked --bins` (`9.34s`), and strips release executables (`demo-dest`, `relay-keygen`, `relay-exit`, `relay-middle`, `relay-entry`, `relay-client`).
- **Runtime Stage:** `debian:bookworm-slim`, non-root user `relay` (`10001:10001`), zero Rust toolchains/compilers/network CLI utilities (`command -v cargo rustc gcc curl wget nc` -> `NO_DEV_OR_NET_TOOLS`).
- **Built Image Inspection (`docker images` / `docker image inspect`):**
  - Tag / ID: `private-relay:v0.1` (`5a0fb72d9438`)
  - Content Size: `32,621,775` bytes (`32.6 MB`); Disk Usage: `128 MB`
  - Configured User: `10001:10001` (`uid=10001(relay) gid=10001(relay)`)

---

## 3. Health-Check Evidence & Graceful Shutdown

- **Health Probe Mechanism:** Pure-Rust TCP connect probe (`/usr/local/bin/relay-client --probe 127.0.0.1:<port>`, `interval: 2s`, `timeout: 3s`, `retries: 15`) verified readiness only after `RelayServer::start` / `demo-dest` bound sockets.
- **`docker compose up -d --wait` Dependency & Readiness Proof:**
  - `private-relay-keygen`: `Exited (0)`
  - `private-relay-dest`: `Up 24 seconds (healthy)`
  - `private-relay-exit`: `Up 18 seconds (healthy)`
  - `private-relay-middle`: `Up 12 seconds (healthy)`
  - `private-relay-entry`: `Up 6 seconds (healthy)`
- **Graceful `SIGTERM` Shutdown (`docker compose stop`):** Verified `wait_for_shutdown_signal()` handled `SIGTERM` cleanly in every daemon container, emitting `relay accept loop shutting down`, `STATUS=SHUTTING_DOWN`, and `STATUS=STOPPED` before `docker compose down -v --remove-orphans` removed all containers, volumes, and `private-relay_relay_net` (`docker ps -a --filter name=private-relay` returned `0` leftover containers).

---

## 4. Container Integration Test Results ([demo/run-docker-demo.ps1](../demo/run-docker-demo.ps1))

Executed `powershell -ExecutionPolicy Bypass -File .\demo\run-docker-demo.ps1 -SkipBuild` against the healthy 5-container topology:

| # | Scenario | Result | Observed Outcome & Timing |
| :--- | :--- | :--- | :--- |
| `1` | Empty raw request (`0B`) | **Passed** | `3-hop circuit_id=2147483649`, `outcome: OK`, `response_bytes: 0`, `elapsed_ms: 18` |
| `2` | Normal HTTP GET (`/health`) | **Passed** | `outcome: OK (http_status="HTTP/1.1 200 OK")`, `response_bytes: 142`, `elapsed_ms: 10` |
| `3` | Medium multi-chunk HTTP (`/medium`) | **Passed** | `outcome: OK (http_status="HTTP/1.1 200 OK")`, `response_bytes: 12375`, `elapsed_ms: 57` |
| `4` | Exact `64 KiB` raw request/response | **Passed** | `request_bytes=65536`, `response_bytes: 65536`, `elapsed_ms: 35` |
| `5` | Exact `64 KiB` HTTP (`/max-64kib`) | **Passed** | `http_status="HTTP/1.1 200 OK"`, `response_bytes: 65536`, `elapsed_ms: 61` |
| `6` | HTTP 302 non-follow (`/redirect-ssrf`) | **Passed** | Returned `302 Found` directly (`112B`, `9ms`) without following `http://169.254.169.254/...` |
| `7` | Oversized request (`65,537B`) | **Passed** | `REJECTED_LOCALLY` (`7ms`), `response_bytes: 0` |
| `8a` | Private RFC1918 target (`10.0.0.1:80`) | **Passed** | `REMOTE_ERROR(PolicyDenied: destination blocked by exit SSRF policy)` (`8ms`) |
| `8b` | Loopback inside container (`127.0.0.1:9000`) | **Passed** | `REMOTE_ERROR(PolicyDenied: destination blocked by exit SSRF policy)` (`9ms`) |
| `8c` | Cloud metadata IP (`169.254.169.254:80`) | **Passed** | `REMOTE_ERROR(PolicyDenied: destination blocked by exit SSRF policy)` (`8ms`) |
| `9` | Oversized dest response (`/oversized`) | **Passed** | `REMOTE_ERROR(PayloadTooLarge: payload exceeded 64 KiB bound)` (`10ms`) |
| `10` | Slow destination timeout (`/slow`, `2500ms`) | **Passed** | `REMOTE_ERROR(Timeout: destination I/O timed out)` (`2513ms`) |

- **Separate Container Log Proof:** `relay-entry`, `relay-middle`, and `relay-exit` each recorded `STATUS=READY`, `relay node started`, and `circuit_hops=12` with zero IP addresses (`172.*`), HTTP paths (`/health`), payloads, or private/public key hex strings leaked.
- **Comparison vs. Windows Bare-Metal Demo:** Identical protocol semantics across all `10+` scenario classes; container run achieved lower loopback-proxy/roundtrip latency (`10ms` `/health`, `35ms` `64 KiB` raw vs. Windows local process spawn `95ms` / `620ms` primarily because Docker relays ran in `--release` profile on Linux while Windows `demo` ran `--dev` binaries) and tested stricter Exit isolation (`allow_loopback_for_test = false` inside Exit's container config, blocking `127.0.0.1` alongside `10.0.0.1` and `169.254.169.254`).

---

## 5. Security Review & Resource Limits

| Security Control | Verified Setting / Observation |
| :--- | :--- |
| **Non-root User** | `User=10001:10001` (`uid=10001(relay)`) verified inside image and all services |
| **Read-Only Root Filesystem** | `read_only: true` on all 6 services (`relay-keygen` writes solely to isolated named config volumes) |
| **Dropped Capabilities & No Escalation** | `cap_drop: [ALL]` and `security_opt: [no-new-privileges:true]` on all 6 services |
| **No Image Secrets / Zero Keys in Git** | `find /cfg -type f` inside `private-relay:v0.1` returned empty; keys exist only ephemerally in runtime named volumes (`down -v` destroys them) |
| **Least-Privilege Volume Isolation** | `relay-entry`, `relay-middle`, `relay-exit`, and `relay-client` each mount `:ro` ONLY their own config volume |
| **No Public Ports / Host Net / Docker Socket** | `ports:` omitted (`PORTS` blank in `docker compose ps`), `relay_net` uses `internal: true`, no `/var/run/docker.sock` mount |
| **Container Resource Limits** | `relay-entry`/`relay-middle`/`relay-exit`: `mem_limit: 128m`, `cpus: 0.50`, `pids_limit: 64`; `demo-dest`/`relay-client`: `64m`, `0.50`, `64`; `relay-keygen`: `64m`, `0.50`, `32` |

### Development Containers vs. Production Deployment Boundary
- **Local Dev Only:** `relay-keygen` shared volume initialization and `allow_private_targets_for_test = true` (`allowed_targets = ["demo-dest:9000"]`) are strictly local integration mechanisms for Docker bridge testing.
- **Production Requirements:** Never embed `allow_private_targets_for_test` or `allow_loopback_for_test` in production; inject per-node keys via dedicated secrets managers / CSI mounts, use signed Coordinator peer discovery, add host/cloud egress firewalls, and perform external cryptographic + penetration audits (`cargo-audit` / `cargo-fuzz`).

---

## 6. Known Limitations

- Single-host Docker Compose bridge (`internal: true`) — multi-host overlay TLS/mesh and WAN NAT traversal remain untested.
- Docker Linux engine was kept running via Docker Desktop on Windows host during verification; Kubernetes, Prometheus metrics, and LLM integrations remain out of scope and unstarted.
- Automated `cargo-audit` / `cargo-deny` CVE scanning remains `NOT EXECUTED` offline inside this environment (`Day 4` report stands).
