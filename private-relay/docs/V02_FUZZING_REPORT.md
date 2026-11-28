# PRIVATE RELAY v0.2 — PROTOCOL FUZZING & ADVERSARIAL TESTING REPORT

**Date:** 2026-11-28  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Status Summary:** Offline Native Mutation Fuzzing (`1,000,044` post-fix executions) & Property Invariant Tests **`VERIFIED OFFLINE`** | Nightly `cargo-fuzz` / `libFuzzer` + ASan **`NOT VERIFIED` (`BLOCKED` offline)**

---

## 1. Boundary Inventory & Toolchain Constraints

Every untrusted-input boundary across the 6-crate workspace was inspected:
1. `crates/protocol`: TCP wire length framing (`decode_wire_record`), padded outer plaintext (`OuterFramePlaintext::unpack_link_frame`), cell decoding/encoding (`Cell::decode`/`encode`), hop plaintext (`RelayHopPlaintext::decode`/`encode`), chunking and reassembly (`InnerPayload::decode`, `MessageReassembler::push`, `DecodedRequest::parse`).
2. `crates/crypto`: `Noise_IK` handshakes (`LinkInitiator`/`LinkResponder`), `Noise_NK` telescopic handshakes (`HopHandshakeInitiator`/`HopHandshakeResponder`), `ChaCha20-Poly1305` per-hop envelopes (`HopCipherState::open`), and `StaticKeypair::from_slices`.
3. `crates/network`: `RelayConfig::from_toml_str`, `ClientConfigFile::from_toml_str`, `RelayConfig::read_public_key_from_toml_str`, `resolve_secret_file`, `decode_hex_32`, and SSRF `DestinationPolicy::resolve_and_validate` / `validate_ip`.
4. `crates/cli`: `parse_sanitized_http_status`, `parse_http_health_response`, `parse_http_request_path`, `build_http_request_from_url`, `DestServerConfig::from_toml_str`, and CLI flag parsers.

**Toolchain Availability Check:**
- `cargo fuzz --version` failed (`error: no such command: fuzz`), `rustup toolchain list` shows only `stable-x86_64-pc-windows-msvc` (`rustc 1.93.1`), and neither `libfuzzer-sys` nor `proptest`/`arbitrary` exists in the offline Cargo cache.
- **Mitigation without violating host/offline rules:** Created libFuzzer-ready harnesses under [fuzz/](../fuzz/Cargo.toml) (`exclude = ["fuzz"]`) **and** built a deterministic compiled `--release` mutation + seed-corpus + invariant/canary fuzz driver ([crates/cli/examples/v02_fuzzer.rs](../crates/cli/examples/v02_fuzzer.rs)) plus 4 permanent property/regression test suites.

---

## 2. Fuzz Targets & Campaign Execution Results (`VERIFIED OFFLINE`)

| Target | Entrypoints Covered | Baseline Execs (`500,044`) | Baseline Findings | Post-Fix Execs (`1,000,044`) | Post-Fix Elapsed | Post-Fix Panics / Failures |
|---|---|---|---|---|---|---|
| `target_1_cell_and_hop_decoder` | `Cell::decode/encode`, `RelayHopPlaintext::decode/encode`, `DecodedRequest::parse` | `100,010` (`153 ms`) | **56 invariant failures** | `200,010` | `201 ms` | `0 / 0` |
| `target_2_frame_and_wire_decoder` | `decode_wire_record`, `OuterFramePlaintext::unpack_link_frame` | `100,005` (`65 ms`) | `0` | `200,005` | `124 ms` | `0 / 0` |
| `target_3_fragment_reassembly` | `InnerPayload::decode`, `MessageReassembler::push` (raw + decoded) | `100,012` (`77 ms`) | *(Static review caught direct-struct panic/alloc bug)* | `200,012` | `259 ms` | `0 / 0` |
| `target_4_http_response_and_url` | `parse_sanitized_http_status`, `parse_http_health_response`, `parse_http_request_path`, `build_http_request_from_url` | `100,006` (`321 ms`) | `0` | `200,006` | `918 ms` | `0 / 0` |
| `target_5_config_and_secret_parser` | `RelayConfig`/`ClientConfigFile`/`DestServerConfig::from_toml_str`, `decode_hex_32`, `DestinationPolicy::validate_ip`, CLI parsers | `50,005` (`1,937 ms`) | **239 secret-canary leaks** | `100,005` | `4,411 ms` | `0 / 0` |
| `target_6_noise_handshake_inputs` | `LinkInitiator/Responder`, `HopHandshakeInitiator/Responder` | `50,006` (`17,875 ms`) | `0` | `100,006` | `39,502 ms` | `0 / 0` |
| **Total** | **6 Targets** | **500,044** | **295 Failures** | **1,000,044** | **45,415 ms** | **0 / 0** |

---

## 3. Defects Discovered, Root Causes & Fixes Verified

1. **Secret Key Leak in TOML Configuration Parse Errors (`target_5`, `239` fuzzer reproductions — High):**
   - **Root Cause:** `RelayConfig::from_toml_str`, `RelayConfig::read_public_key_from_toml_str`, and `ClientConfigFile::from_toml_str` (`crates/network/src/config.rs`), plus `DestServerConfig::from_toml_str` (`crates/cli/src/lib.rs`), formatted `toml::de::Error` using `.to_string()`, whose `Display` prints a multi-line source snippet around the syntax error — leaking neighboring `private_key_hex = "..."` lines into returned error messages/stderr.
   - **Fix:** Added `sanitize_toml_error(err: &toml::de::Error)` formatting strictly `err.span()` byte offsets and `err.message()`, never source line text.
   - **Regression Test:** `fuzz_regression_toml_parse_errors_never_leak_inline_private_key` ([crates/network/tests/fuzz_config_tests.rs](../crates/network/tests/fuzz_config_tests.rs)).

2. **Asymmetric Length Bound in `RelayHopPlaintext::decode` (`target_1`, `56` fuzzer reproductions — Medium):**
   - **Root Cause:** `RelayHopPlaintext::decode` accepted `RelaySubCommand::Forward` (`0x01`) and `RelaySubCommand::Message` (`0x03`) payloads with `rest.len() >= MAX_CELL_BODY_LEN` (`571B+`, e.g., reproduced `737B` payload from mutated `len=738B`), whereas `RelayHopPlaintext::encode` strictly rejects `>= 571B`, violating canonical decode/encode symmetry.
   - **Fix:** Enforced `if rest.len() >= MAX_CELL_BODY_LEN` returning `ProtocolError::PayloadTooLarge` inside `RelayHopPlaintext::decode` ([crates/protocol/src/cell.rs](../crates/protocol/src/cell.rs)).
   - **Regression Test:** `fuzz_regression_oversized_hop_plaintext_forward_and_message_rejected` ([crates/protocol/tests/fuzz_property_tests.rs](../crates/protocol/tests/fuzz_property_tests.rs)).

3. **Unvalidated Struct Panic / Allocation Guard in `MessageReassembler::push` & `Cell::encode` (`crates/protocol` — Medium):**
   - **Root Cause:** `InnerPayload`'s struct fields are `pub`; calling `MessageReassembler::push` directly with a manually constructed `InnerPayload` (bypassing `new()`/`decode()`) could pass `chunk_count = 65535` (`vec![false; 65535]` over-allocation) or `flags = ERROR` with empty `fragment` (causing an index-out-of-bounds panic at `chunk.fragment[0]`). Similarly `Cell::encode` did not validate `Destroy` reason length symmetrically with `Cell::decode`.
   - **Fix:** Validated `validate_chunk_metadata` at entry to `MessageReassembler::push` ([crates/protocol/src/message.rs](../crates/protocol/src/message.rs)) and validated `self.destroy_reason()?` in `Cell::encode_into_slice` ([crates/protocol/src/cell.rs](../crates/protocol/src/cell.rs)).
   - **Regression Test:** `fuzz_regression_reassembler_rejects_unvalidated_struct_without_panic_or_alloc`.

---

## 4. Property & Invariant Test Suites Added (`VERIFIED OFFLINE`)

- [crates/protocol/tests/fuzz_property_tests.rs](../crates/protocol/tests/fuzz_property_tests.rs) (`4` tests): randomized `Cell`/`OuterFramePlaintext`/`RelayHopPlaintext`/`ExtendDirective`/`wire_record` round-trips (`500` cases), insufficient padding rejection, invalid wire record length rejection, `0B..64 KiB` chunking/reassembly boundary tests, ordering/duplicate/missing/wrong-`RequestId`/oversized rejection, and error code invariance.
- [crates/crypto/tests/fuzz_handshake_tests.rs](../crates/crypto/tests/fuzz_handshake_tests.rs) (`2` tests): exhaustive truncation (`0..len`) and per-byte bit-flip fuzzing over `Noise_IK` & `Noise_NK` `msg1`/`msg2`, plus permanent fail-closed link session check after wire corruption.
- [crates/network/tests/fuzz_config_tests.rs](../crates/network/tests/fuzz_config_tests.rs) (`2` tests): TOML canary non-leak regression, directory/oversized secret file rejection, `Debug`/scrub checks, malformed `host:port`, and SSRF IPv4/IPv6 bypass coverage.
- [crates/cli/tests/fuzz_http_tests.rs](../crates/cli/tests/fuzz_http_tests.rs) (`1` test): control-character stripping, 64-byte status bounding, malformed HTTP `/health` rejection, and URL injection rejection.
