# Technology Stack & Engineering Foundation — Private-Relay (`Phase 2`)

> Consolidates stack evaluation, alternatives, trade-offs, and stage gating (`v0.1` vs `Phase 6–12`). See also [docs/TECH_DECISIONS.md](./docs/TECH_DECISIONS.md).

---

## 1. Stack Evaluation & Stage Assignment

| Layer | Selected Choice | Why Necessary | Alternatives & Trade-Offs | Target Phase |
| :--- | :--- | :--- | :--- | :--- |
| **Core Language** | **Rust (`1.93.1`, MSVC on Windows)** | Memory safety, fearless concurrency, deterministic drop/zeroization without GC latency spikes. | C/C++ (memory corruption hazard), Go (GC pauses + weaker zeroization guarantees). | **Phase 3–4 (v0.1)** |
| **Async I/O** | **Tokio** | High-concurrency non-blocking TCP sockets, timers, bounded channels (`mpsc`), clean shutdown signals. | OS threads (scales poorly past hundreds of sockets), `async-std` (smaller ecosystem). | **Phase 3–4 (v0.1)** |
| **Crypto Suite** | **`snow` + RustCrypto (`chacha20poly1305`, `hkdf`, `sha2`, `ed25519-dalek`, `zeroize`)** | Reviewed Noise + RFC implementations; pure Rust compiles cleanly on Windows MSVC without OpenSSL/C-toolchain issues. | `ring` (C/asm build complexity on Windows), custom crypto (strictly forbidden). | **Phase 3–5 (v0.1)** |
| **Link Transport** | **TCP** (`v0.1`), evaluate **QUIC (`quinn`)** later | Reliable FIFO byte stream simplifies per-hop monotonic sequence checks initially; traverses restrictive NATs. | UDP + custom ARQ (reinvents transport), QUIC upfront (adds UDP/ALPN complexity before proving circuit logic). | **Phase 4 (v0.1)** |
| **Configuration** | **TOML (`toml` + `serde`)** | Strongly typed startup schema; catches bad keys/ports/limits immediately. | YAML (indentation pitfalls), JSON (no comments). | **Phase 4 (v0.1)** |
| **Directory API** | **Axum (HTTP/JSON)** | Needed only once dynamic relay registration & health endpoints justify a Coordinator service. | `tonic`/gRPC (overkill for small JSON descriptor pulls), raw sockets (harder to inspect). | **Phase 6** |
| **Persistence** | **PostgreSQL (`sqlx`)** | Durable relational store for relay registrations/uptime history if Coordinator runs across restarts. | SQLite (good bridge for single-node dev), premature DB in v0.1 adds needless setup friction. | **Phase 6** |
| **Observability** | **Prometheus + Grafana** (+ sanitized `tracing`) | Privacy-safe aggregate gauges/counters without per-request tracing leaks. | Full OpenTelemetry request spans across relays (violates unlinkability!). | **Phase 9** |
| **Containers** | **Docker + Docker Compose** | Reproducible Linux relay isolation & multi-node local simulation before cloud hosts. | Direct Windows binaries (`127.0.0.1` ports) suffice for Phase 4–5 debugging. | **Phase 8 / 12** |
| **UI Integration** | **Frontend (`relay-site` / Next.js)** | Connects to real Coordinator/telemetry APIs once backend produces verified metrics. | Connecting before real backend capabilities risks misrepresenting prototypes as live infra. | **Phase 10** |
| **Deferred Extensibility** | **Kubernetes Readiness + Optional LLM Abstraction** | Prepare containerized health/readiness & config externalization; keep optional LLM provider trait mocked only. | Live K8s deployment & live LLM credentials **explicitly deferred** until user authorization. | **Phase 12+ (Auth Required)** |

---

## 2. Anti-Overengineering Guardrails

- **No Microservices in `v0.1`:** `Entry`, `Middle`, and `Exit` run from **one shared `relay` crate/binary** configured by `role` in `relay.toml`.
- **No Unnecessary Workspace Crates:** Only create `protocol`, `crypto`, `relay`, and `client` once we implement each crate sequentially—never create empty crate stubs.
- **No External DB in `v0.1`:** Static `relays.toml` drives Phases 4–5 until dynamic registration (`Phase 6`) justifies a coordinator & database.
