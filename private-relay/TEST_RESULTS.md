# Test & Verification Results (`TEST_RESULTS.md`)

> **Verification Standard:** Only tests and environment checks actually executed locally are recorded here. Unrun tests are explicitly marked as *Not Yet Executed*.

---

## 1. Environment Checks Executed

| Check | Date | Environment | Command | Observed Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Rust compiler & Cargo | `2026-11-26` | Windows PowerShell | `rustc --version; cargo --version` | `rustc 1.93.1 (01f6ddf75 2026-02-11)` / `cargo 1.93.1 (083ac5135 2025-12-15)` | **Verified** |
| Active toolchain & MSVC linker | `2026-11-26` | Windows PowerShell | `rustup toolchain list` + VS2022 `link.exe` lookup | `stable-x86_64-pc-windows-msvc (active, default)` + MSVC `14.44.35207` `link.exe` present | **Verified** |

---

## 2. Protocol & Security Tests

| Suite | Target Phase | Status | Notes |
| :--- | :--- | :--- | :--- |
| Wire framing (`600B` link frames, cell bounds, fuzzing) | Phase 3 | **Not Yet Executed** | `crates/protocol` not created yet |
| Noise handshake, HKDF separation, AEAD tamper & replay rejection | Phase 4–5 | **Not Yet Executed** | `crates/crypto` not created yet |
| Exit SSRF IP-blocklist & DNS-at-Exit isolation | Phase 4–5 | **Not Yet Executed** | `crates/relay` not created yet |
| 3-hop local E2E (`Client → Entry → Middle → Exit → Dest`) | Phase 4 | **Not Yet Executed** | Awaits Phase 4 completion |
| Concurrency / Backpressure / Slowloris benchmarks | Phase 7–8 | **Not Yet Executed** | Planned |
