# PRIVATE RELAY v0.3 — CRYPTOGRAPHIC KEY LIFECYCLE & MEMORY SAFETY REPORT

**Date:** 2026-11-28  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Status Summary:** Application Key-Lifecycle Hardening, Custom `snow` `ZeroizingCryptoResolver` & Regression Tests **`VERIFIED OFFLINE`** | Upstream `snow` Stack/Chaining-Key & HKDF Internal State Boundaries **Documented Honestly** | External Audit **`NOT VERIFIED`**

---

## 1. Scope & Upstream Inspection Summary

Audited the full secret, nonce, and plaintext memory lifecycle across all six crates (`crates/protocol`, `crates/crypto`, `crates/network`, `crates/relay`, `crates/client`, `crates/cli`) alongside the exact vendored/cached upstream sources in `Cargo.lock`:
- `snow v0.9.6` (`handshakestate.rs`, `symmetricstate.rs`, `cipherstate.rs`, `transportstate.rs`, `types.rs`, `builder.rs`, `resolvers/default.rs`, `resolvers/mod.rs`)
- `chacha20poly1305 v0.10.1` & `chacha20 v0.9.1` (verified `impl Drop` + `ZeroizeOnDrop` on `ChaChaPoly1305` and `ChaChaCore`)
- `hkdf v0.12.4`, `hmac v0.12.1`, `digest v0.10.7` (verified `digest` in `Cargo.lock` does **not** activate a `zeroize` feature)
- `zeroize v1.9.2` (verified `Zeroizing<Z>` & `String::zeroize()` volatile zero-fill behavior)

Zero `unsafe` blocks exist anywhere in first-party `crates/*/src/`. No memory-pinning/locking (`mlock`/`VirtualLock`) or `unsafe` pointer casts were introduced.

---

## 2. Secret Material Lifecycle Matrix

| Secret Material | Owner & Location | Lifecycle (Creation -> Drop/Clear) | Protection Mechanism (`v0.3`) | Residual Risk | Verification Status |
|---|---|---|---|---|---|
| Static X25519 Private Key (`[u8; 32]`) | `StaticKeypair` (`crates/crypto/src/keys.rs`) | Startup config load / ephemeral `StaticKeypair::generate()` -> process exit or circuit teardown | `Zeroizing<[u8; 32]>`, `#[derive(Zeroize, ZeroizeOnDrop)]`, `[REDACTED]` `Debug`; `kp.private.zeroize()` in `generate()` | Stack parameter/register copies during curve clamp or `decode_hex_32` | **VERIFIED OFFLINE** (`key_lifecycle_tests`) |
| `snow` Handshake `s_dh` / `e_dh` Boxed State (`Dh25519`) | `LinkInitiator`, `LinkResponder`, `HopHandshakeInitiator`, `HopHandshakeResponder` | Handshake init -> `into_transport_mode()` OR error / timeout / task drop | **`ZeroizingCryptoResolver`** (`ZeroizingDh::drop` overwrites `privkey` with zeros via `Dh::set(&[0; 32])`) | Rust compiler stack/LLVM register copies inside `curve25519-dalek` scalar ops | **VERIFIED OFFLINE** (`key_lifecycle_tests` `(2, 3, 1)` drop proof) |
| `snow` Handshake & Transport Ciphers (`CipherChaChaPoly`) | `LinkSession::transport`, handshake `cipherstates` | Noise handshake `split()` / rekey -> `LinkSession::drop` or failed `UnexpectedPeerIdentity` | `ZeroizingCipher::drop` + `LinkSession::drop` (`rekey_manually` zeroes) + explicit `rekey_manually` wipe on `UnexpectedPeerIdentity` | Noise `Cipher::rekey()` stack temporary array `[u8; 48]` in `snow/src/types.rs` | **VERIFIED OFFLINE** |
| `snow` Hash State (`HashBLAKE2s`) & `SymmetricStateData` (`ck`) | `snow::HandshakeState::symmetricstate` | Noise mix/split -> `HandshakeState` drop / `into_transport_mode()` | `ZeroizingHash::drop` calls `Hash::reset()` | **Upstream Gap:** `SymmetricStateData.ck` (`[u8; 64]`), stack `dh_out`/`hkdf_output`/`ipad`/`opad` inside `snow 0.9.6` lack upstream `Zeroize` | **Documented Honestly** |
| `Noise_NK` Seeds (`c_seed`, `r_seed`, `ikm`, `k_fwd`, `k_bwd`) | `crates/crypto/src/hop.rs` | Random generation (`OsRng`) -> HKDF expansion -> `HopCipherPair` | `Zeroizing<[u8; 32]>` / `Zeroizing<[u8; 64]>` | `Hkdf::<Sha256>` embeds `HmacCore` (`Sha256Core` PRK digest); `digest v0.10.7` in `Cargo.lock` lacks `zeroize` feature | **VERIFIED OFFLINE** (app wrappers) / **Upstream Gap** (`Hkdf` struct) |
| Per-Hop AEAD Keys & Schedules (`ChaCha20Poly1305`) | `HopCipherState`, `HopCipherPair`, `ClientCircuitCrypto` | Hop handshake completion -> circuit close / timeout / destroy | `#[derive(ZeroizeOnDrop)]`; upstream `ChaChaPoly1305::drop` zeroes `key` + stream cipher state; `[REDACTED]` `Debug` | Stack copies during `ChaCha20Poly1305::new_from_slice` | **VERIFIED OFFLINE** |
| Padding PRNG State (`StdRng`) | `LinkSession::pad_rng` (`crates/crypto/src/link.rs`) | Seeded strictly via `OsRng` (fail-closed in `v0.3`) -> frame padding -> session drop | `LinkSession::drop` overwrites `self.pad_rng = StdRng::from_seed([0u8; 32])` | Padding itself is non-secret pseudorandom fill; zero-seed overwrite scrubs state on teardown | **VERIFIED OFFLINE** |
| Config TOML / Hex Secret Strings | `RelayConfig`, `crates/cli/src/lib.rs`, `crates/network/src/config.rs` | Config read / keygen -> scrubbed after `keypair()` (`RelayServer::start`) or `Drop` | `Drop for RelayConfig`, `scrub_private_key()`, `without_inline_secret()` now calls `.zeroize()`, `decode_hex_32_zeroizing()`, `Zeroizing<String>` around TOML reads/keygen files | Temporary TOML parser string slices while deserializing (bounded at `512 KiB`) | **VERIFIED OFFLINE** (`fuzz_config_tests`) |
| Transient Outer/Hop Plaintexts & Partial Fragments | `LinkSession`, `ClientCircuitCrypto`, `MessageReassembler`, `engine.rs`, `client.rs` | Per-cell encrypt/decrypt or chunk reassembly -> forward/deliver | `Zeroizing<[u8; 582]>` outer buffers, `Zeroizing<Vec<u8>>` hop/message buffers, **`Drop for MessageReassembler`** (`buffer.fill(0)` on early abort/timeout) | Final returned application response `Vec<u8>` owned by caller CLI/library (`client::send_request`) | **VERIFIED OFFLINE** |

---

## 3. Defects Found & Fixes Implemented in `v0.3`

1. **`snow` Heap Key & Handshake Primitive Retention (`crates/crypto/src/keys.rs`, `hop.rs`, `link.rs`):**
   - *Root Cause:* Inspecting `snow 0.9.6` confirmed `Dh25519`, `CipherChaChaPoly`, and `HashBLAKE2s` inside `DefaultResolver` implement no `Drop` zeroization. Consequently, dropping a `HandshakeState` (including on `into_transport_mode()`, cancelled `HopHandshakeInitiator`, `HopHandshakeResponder` holding the relay's static private key, or handshake error paths) left unzeroized key material in heap allocations.
   - *Fix:* Implemented `ZeroizingCryptoResolver` wrapping `DefaultResolver`'s boxed `Dh`, `Cipher`, and `Hash` objects in explicit `Drop` guards (`Dh::set(&zeros)`, `Cipher::set(&zeros)`, `Hash::reset()`), wired across `LinkInitiator`, `LinkResponder`, `HopHandshakeInitiator`, `HopHandshakeResponder`, `StaticKeypair::generate()`, and `StaticKeypair::from_slices()`. Also added `kp.private.zeroize()` in `StaticKeypair::generate()`.
2. **`LinkInitiator::finish_with_msg2` Error-Path Scrubbing & Fail-Closed Padding RNG (`crates/crypto/src/link.rs`):**
   - *Root Cause:* When `extract_remote_static` failed or mismatched `expected_remote_pub`, the newly split `snow::TransportState` dropped directly without `LinkSession::drop` running. Furthermore, `LinkSession::new` fell back to a fixed constant seed `[0xA5; 32]` if `OsRng` errored.
   - *Fix:* Added explicit `transport.rekey_manually(Some(&zeros), Some(&zeros))` on mismatch/extraction errors alongside `ZeroizingCipher`, converted `LinkSession::new` to `Result`, failed closed on `StdRng::from_rng(OsRng)`, and switched `padding`/`plain`/`pt_buf` to `Zeroizing` RAII guards.
3. **`RelayConfig::without_inline_secret` & Hex/CLI Buffer Scrubbing (`crates/network/src/config.rs`, `crates/cli/src/lib.rs`):**
   - *Root Cause:* `without_inline_secret` replaced `cloned.private_key_hex = String::new()`, deallocating the cloned 64-hex-char secret buffer without zeroizing it first; `write_secret_key_file` and `generate_demo_configs_with_options` allocated unguarded `String`s for keys/TOML files; `decode_hex_32` returned raw stack `[u8; 32]` for secret keys.
   - *Fix:* Fixed `without_inline_secret` to call `cloned.private_key_hex.zeroize()`, added `decode_hex_32_zeroizing`, wrapped `write_secret_key_file` & inline TOML serialization in `Zeroizing`, and added `scrub_private_key()` calls after keygen serialization.
4. **Early-Abort Fragment & Relay Plaintext Scrubbing (`crates/protocol/src/message.rs`, `crates/relay/src/engine.rs`, `crates/client/src/client.rs`):**
   - *Fix:* Implemented `Drop for MessageReassembler` (`self.buffer.fill(0)`, zero cost on normal completion since `std::mem::take` empties `buffer`), wrapped intermediate forward onion buffer `next_buf` in `Zeroizing`, and wrapped relay/client decrypted hop/message/request plaintexts in `Zeroizing`.

---

## 4. Regression Tests & Explicit Guarantees Boundary

- **Added Regression Suite:** [crates/crypto/tests/key_lifecycle_tests.rs](../crates/crypto/tests/key_lifecycle_tests.rs) (`3/3` passing) verifies exact resolver scrub counts (`(dh_zeroed=2, cipher_zeroed=3, hash_reset=1)`) across completed handshakes, wrong-key rejection, truncated message failure, mid-handshake cancellation, and redacted `Debug` formatting.
- **Explicit What Rust & Application Code Cannot Guarantee:**
  1. Compiler-emitted register spills or transient LLVM stack copies inside `curve25519-dalek` / `snow` internal arrays (`HandshakeState::symmetricstate.inner.ck`, stack `dh_out`, `hkdf_output`, `Cipher::rekey()` temporaries, `Hkdf::<Sha256>` `HmacCore` PRK digests without `digest/zeroize`).
  2. Host OS page swap, hibernation files, debugger attachment, or kernel core dumps (mitigated in K8s/Docker via non-root `UID 10001`, `cap_drop: [ALL]`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, though OS `mlock` is not used).
