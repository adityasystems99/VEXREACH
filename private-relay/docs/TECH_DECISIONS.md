# Technology Decision Record — Private-Relay (`v0.1` → Future)

Each choice below separates **v0.1 MVP necessity** from **later-stage components** so we never drag unnecessary operational complexity into Phases 2–4.

---

| Technology | Why Needed | Alternatives Considered | Trade-Offs | Stage |
| :--- | :--- | :--- | :--- | :--- |
| **Rust (`1.93+`)** | Memory safety without GC pauses; strong type system prevents buffer overflows & lifetime races in concurrent relay routers; `zeroize` support for key hygiene. | Go, C++, Zig | Steeper initial borrow-checker discipline for async state machines (`tokio`), much safer long-term security posture than C/C++. | **v0.1 Core** |
| **Tokio** | Industry-standard Rust async runtime for non-blocking TCP sockets, timers, bounded channels (`mpsc`), and clean task cancellation. | `async-std`, raw `mio`, std threads | Adds macro/executor complexity, avoids OS thread-per-circuit explosion (`1024+` circuits cleanly). | **v0.1 Core** |
| **TCP (initial link transport)** | Reliably traverses firewalls/NATs; in-order delivery simplifies sequence-based replay counters (`seq == expected_seq`) in Phases 2–4. | UDP + custom ARQ, **QUIC (`quinn`)** | Multiplexed TCP circuits suffer head-of-line blocking under packet loss; simpler and far easier to debug on Windows initially. Re-evaluate QUIC after Phase 6 metrics. | **v0.1 Core** (`QUIC` evaluated later) |
| **`snow` (Noise Framework)** | Audited Rust implementation of Noise patterns (`Noise_IK`, `Noise_NK`); eliminates hand-rolled DH transcripts and state bugs. | Raw `rustls` + custom X25519 circuit handshake | Requires clean framing wrapper (`600B` link frames) around raw TCP reads/writes; lightweight vs full X.509 PKI. | **v0.1 Core (`Phase 2`)** |
| **`chacha20poly1305` + `hkdf` + `x25519-dalek` + `zeroize` (RustCrypto)** | Constant-time, pure-Rust audited AEAD and key-derivation crates with clean memory zeroization. | `ring`, `openssl` (FFI) | `ring` has C/assembly toolchain quirks on some Windows setups; RustCrypto (`chacha20poly1305`, `hkdf`) compiles smoothly on Windows MSVC without external C libs. | **v0.1 Core (`Phase 2`)** |
| **TOML (`toml` + `serde`)** | Human-auditable config files for relay ports, roles, resource limits, and static `v0.1` peer descriptors. | YAML, JSON, env-only | Typed deserialization catches misconfigured limits or invalid keys at startup before opening sockets. | **v0.1 Core (`Phase 3`)** |
| **Axum (HTTP API)** | Clean async Rust HTTP framework for Coordinator directory API (`/relays`, `/health`) and future frontend integration. | `actix-web`, `warp`, gRPC (`tonic`) | Unnecessary during local single-file static directory phases (`v0.1`); introduces HTTP parsing surface earlier than needed. | **Phase 5 (`Coordinator`)** |
| **PostgreSQL** | ACID persistence for relay operator registrations, signed descriptor history, and uptime/health tracking in multi-node directories. | SQLite, in-memory JSON | Requires running a DB server; overkill while `v0.1` runs locally from `relays.toml`. (SQLite can bridge single-node testing in early Phase 5.) | **Phase 5+** |
| **Prometheus + Grafana** | Low-overhead aggregate counters/gauges (`active_circuits`, `latency_ms`) without storing sensitive per-request logs. | OpenTelemetry full tracing everywhere, custom CSV | Full distributed request tracing conflicts with relay unlinkability! Only aggregate counters/histograms belong in relay telemetry. | **Phase 6** |
| **Docker** | Reproducible Linux container builds for simulating isolated Entry/Middle/Exit network namespaces and cloud deployment. | Raw Windows binaries only | Local Windows `127.0.0.1:<port>` processes are faster to iterate on in Phases 2–4; Docker shines when testing multi-node firewall/SSRF isolation. | **Phase 7–8** |
| **Frontend (React / Next.js)** | Developer architecture explorer and honest live-vs-simulated telemetry display once backend endpoints exist. | Terminal CLI only | Must **never** precede real relay testing (`Phase 9`). | **Phase 9** |

---

### Explicit Decisions Locked for `v0.1` (`Phases 2–4`)
1. **Decision D-01 (Bounded Messages First):** Implement fixed-size cell-segmented request/response forwarding (`<= 64 KiB`) with `request_id` + `stream_id`-ready header before tackling long-lived SOCKS5 streaming windows.
2. **Decision D-02 (Pure RustCrypto + `snow`):** Prefer `snow` + RustCrypto (`chacha20poly1305`, `hkdf`, `zeroize`) over C FFI libraries so Windows VS Code builds remain frictionless and auditable.
3. **Decision D-03 (Defer Coordinator / DB / Docker):** Start Workspace `private-relay/` in Phase 2 with only active, non-empty crates (`protocol`, `crypto`, `relay`, `client`)—adding `coordinator` in Phase 5.
