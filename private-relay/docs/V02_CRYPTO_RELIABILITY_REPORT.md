# PRIVATE RELAY v0.2 — CRYPTOGRAPHIC TRANSPORT RELIABILITY & SOAK REPORT

**Date:** 2026-11-28  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Status Summary:** Noise Implementation Audit, Key Lifecycle Review, 10 Rekey Stress Scenarios & 5-Minute (`300.17s`) Live 3-Hop Soak Test **`VERIFIED OFFLINE`** | Extended 30-Minute Soak **`NOT VERIFIED`** *(harness `--duration-secs 1800` provided)*

---

## 1. Direct Source Audit of `snow 0.9.6` & `crates/crypto` (`VERIFIED OFFLINE`)

Rather than relying on crate documentation alone, the actual cached upstream `snow-0.9.6` source (`src/transportstate.rs`, `src/cipherstate.rs`, `src/handshakestate.rs`, `src/types.rs`, `src/resolvers/default.rs`) was inspected alongside `crates/crypto/src/{link.rs,hop.rs,keys.rs}`:

1. **Transport State & Nonce Progression (`transportstate.rs`, `cipherstate.rs`):**
   - `CipherState::encrypt_ad` / `decrypt_ad` validates `n != u64::MAX`, uses `u64::to_le_bytes` for Noise `ChaChaPoly`, and strictly increments `self.n += 1`. `u64::MAX` (`2^64 - 1`) returns `StateProblem::Exhausted`.
   - `TransportState::rekey_outgoing()` and `rekey_incoming()` delegate to `Cipher::rekey()`, which encrypts 32 zero bytes at reserved nonce `u64::MAX` and calls `self.set(&ciphertext[..32])` per Noise Specification Section 4.2 — **never resetting `self.n`**.
2. **Fixes Applied Following Audit:**
   - **Link Nonce Ceiling Enforcement Near `2^48` ([crates/crypto/src/link.rs](../crates/crypto/src/link.rs)):** `LinkSession::should_rekey_outgoing()` previously returned `true` when `sending_nonce() >= MAX_LINK_NOISE_NONCE` (`2^48`), while `seal_rekey_and_rotate()` lacked a `sending_nonce() >= MAX_LINK_NOISE_NONCE` guard (allowing an automatic `RekeyControl` frame to still encrypt at nonce `2^48` because Noise `rekey()` does not reset `n`). Fixed so `should_rekey_outgoing()` returns `false` once `sending_nonce() >= nonce_limit` and `seal_rekey_and_rotate()` explicitly fails closed (`self.failed = true; Err(CryptoError::SequenceExhausted)`).
   - **Zeroization of `snow::TransportState` Cipher Buffers on Drop ([crates/crypto/src/link.rs](../crates/crypto/src/link.rs)):** Inspection of `snow-0.9.6/src/resolvers/default.rs` showed `CipherChaChaPoly { key: [u8; 32] }` and `Dh25519 { privkey: [u8; 32], pubkey: [u8; 32] }` do **not** implement `Drop` or `Zeroize`. Added `impl Drop for LinkSession` calling `self.transport.rekey_manually(Some(&[0u8; 32]), Some(&[0u8; 32]))` and resetting `pad_rng` to scrub active link keys explicitly on drop.
   - **Upstream Remaining Boundary (`HandshakeState` Transient Keys):** Within `snow 0.9.6`, handshake-phase `HandshakeState` (`Dh25519` ephemeral scalar & stack buffer in `Cipher::rekey`) still lacks upstream `ZeroizeOnDrop`; replacing `DefaultResolver` or upstream `snow` remains a clean post-`v0.2` hardening candidate.

---

## 2. Rekey Stress Scenarios Verified (`VERIFIED OFFLINE`)

Executed in [crates/crypto/tests/rekey_stress_tests.rs](../crates/crypto/tests/rekey_stress_tests.rs) and [crates/network/tests/rekey_transport_tests.rs](../crates/network/tests/rekey_transport_tests.rs):

| # | Scenario | Result | Observed Verification Evidence |
|---|---|---|---|
| 1 | Rekey before threshold | **VERIFIED OFFLINE** | Explicit `seal_rekey_and_rotate` & `should_rekey_outgoing() == false` below `3 * 600B` |
| 2 | Rekey at threshold | **VERIFIED OFFLINE** | Exact trigger at `bytes_since_rekey == 1800B` and time threshold `max_age` |
| 3 | Simultaneous bidirectional traffic | **VERIFIED OFFLINE** | Concurrent `tokio::join!` client/server TCP `400 + 400` bidirectional cells over `max_bytes = 2400B` (`>= 95` TX & `>= 95` RX rotations) |
| 4 | Consecutive rekeys | **VERIFIED OFFLINE** | `10` back-to-back `LinkSession` rotations synchronized + `3` consecutive TCP `trigger_rekey()` (`< 4` DoS cap) |
| 5 | Rekey during high traffic | **VERIFIED OFFLINE** | `2,000` bidirectional cells at `4`/`5`-frame thresholds (`250` client + `199` server rotations), exact epoch & nonce match |
| 6 | Invalid rekey control frames | **VERIFIED OFFLINE** | Bad magic `BADMAGIC`, epoch `0`, tampered rekey tag -> rejected (`AuthenticationFailed`) + session `is_failed()` |
| 7 | Lost or reordered rekey frames | **VERIFIED OFFLINE** | Dropping `RekeyControl` or delivering `RekeyControl` ahead of preceding cell -> immediate `AuthenticationFailed` & permanent fail-closed state |
| 8 | Transport state synchronization | **VERIFIED OFFLINE** | Verified `outgoing_epoch == peer.incoming_epoch` and `sending_nonce == peer.receiving_nonce` without ever resetting nonces |
| 9 | Attempted nonce exhaustion | **VERIFIED OFFLINE** | Tightened `set_nonce_limit_for_test(2)` verifies `seal_rekey_and_rotate` + `seal_cell` both refuse at limit; real `1u64 << 48` receiving nonce via `set_receiving_nonce_for_test` triggers `SequenceExhausted`; `HopCipherState` `2^32` triggers `SequenceExhausted` |
| 10 | Behavior when rekey fails & flood DoS | **VERIFIED OFFLINE** | `5` consecutive un-spaced `RekeyControl` frames trigger `NetworkError::Protocol` (`MAX_CONSECUTIVE_REKEYS=4`); failed sessions reject all future `seal`/`open` calls |

---

## 3. Bounded Long-Duration Soak Test Results (`v02_soak.rs`)

Harness: [crates/cli/examples/v02_soak.rs](../crates/cli/examples/v02_soak.rs) running live 3-hop `Entry -> Middle -> Exit -> Destination` relays (`rekey_bytes = 65,536 B`, `rekey_interval_secs = 15s`, cyclic `0 B`–`64 KiB` payloads + periodic `169.254.169.254:80` SSRF checks):

### Run A: Initial Unpaced 4-Worker Burst (OS `TIME_WAIT` Saturation Observation)
- **Observation (`target/soak_300s.txt`):** Reached `14,486` requests in ~`40s` (`~390 req/s`) before hitting Windows 11's `~16,384` dynamic ephemeral loopback port limit (`120s` `TIME_WAIT` on Exit `TcpStream::connect` to `127.0.0.1`), producing cyclic pauses where port exhaustions returned `ConnectFailed`/`conn_drops` (`244` request errors, `22,317` client dial drops) while recovering cleanly once `TIME_WAIT` expired (`43,371` total ok requests, `10,183,051` frames received, **`108,715` live Noise rekeys**, **`0` auth failures**, `20.27 -> 24.50 MiB` working set, `post_active_circuits=(0,0,0)`).
- **Finding Fixed (`metrics.rs` / `engine.rs`):** Revealed that `RelayMetrics::add_bytes_sent` incremented `frames_sent_total` by `1` per coalesced TCP batch (`633k` vs `10.18M` rx); added `add_sent_frames(frames, bytes)` for exact frame accounting.

### Run B: Paced 5-Minute Clean Soak Validation (`v02_soak.exe 300 4`, **`VERIFIED OFFLINE`**)

| Metric Tracked | Observed `300.17s` Soak Result |
|---|---|
| **Duration / Exit** | `300.17s` (`5` minutes continuous, Exit code **`0`**) |
| **Successful Requests** | **`23,700`** (`0B..64KiB` verified XOR-echo integrity) + **`118`** SSRF denials |
| **Failed / Unexpected Errors** | **`0`** |
| **Connection Drops / Restarts** | **`0`** unexpected drops (`240` intentional circuit rotations); **`0`** restarts |
| **Relayed Frames (`RX` / `TX`)** | **`5,524,700`** received / **`5,524,460`** sent (`99.996%` 1:1 ratio) |
| **Live Noise Link Rekeys** | **`60,075`** cryptographic key rotations |
| **Authentication Failures** | **`0`** |
| **Post-Soak Active Circuits** | **`(0, 0, 0)`** across Entry, Middle, Exit (`0` leaks) |
| **Process Memory (Working Set / Private)** | Started `16.50 / 11.88 MiB` (`t=10s`), peak `22.88 / 18.34 MiB`, end `22.37 / 17.20 MiB` (**no leak**) |
| **CPU Consumption** | `246.98s` total CPU time across `300s` (`~5.1%` of 16-thread host) |

- **Scope Boundary:** Extended **30-minute (`1800s`) soak validation** and multi-hour multi-host runs remain **`NOT VERIFIED`** in this sprint; the harness supports `--duration-secs 1800` directly.

---

## 4. Key Lifecycle & Non-Leakage Review (`VERIFIED OFFLINE`)

- **`ZeroizeOnDrop`:** Enforced across `StaticKeypair`, `HopCipherPair`, `HopCipherState` (including `ChaCha20Poly1305` cipher schedule), `ClientCircuitCrypto`, `LinkSession` (explicit `rekey_manually` zero key wipe + PRNG seed wipe), `RelayConfig`, and transient key/plaintext buffers (`packed.bytes.zeroize()`, `pt_buf.zeroize()`, `c_seed`/`r_seed: Zeroizing`).
- **`Debug` & Error Output:** `StaticKeypair`, `HopCipherState`, and `RelayConfig` redact secret fields as `"[REDACTED]"`; TOML syntax error messages no longer echo source lines (`sanitize_toml_error` fix); CLI `raw_toml` config buffer in [crates/cli/src/lib.rs](../crates/cli/src/lib.rs) now wraps file contents in `Zeroizing<String>` dropped immediately after parsing before async server execution.
- **Secret Files:** `RelayConfig::resolve_secret_file` enforces regular-file check + `256`-byte max cap + `without_inline_secret` omission on `ConfigMap` serialization.
