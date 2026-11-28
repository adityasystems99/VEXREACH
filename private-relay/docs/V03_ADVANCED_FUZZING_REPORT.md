# PRIVATE RELAY v0.3 — EXTENDED FUZZING & ADVERSARIAL PROTOCOL TESTING REPORT

**Date:** 2026-11-28  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Status Summary:** Extended Offline Native Mutation Fuzzing (`2,000,048` execs, `0` failures) & Expanded Adversarial Property Suites **`VERIFIED OFFLINE`** | Nightly `cargo-fuzz` (`libFuzzer`) + AddressSanitizer (ASan) **`NOT VERIFIED` (`BLOCKED` offline)**

---

## 1. Fuzz Targets & Toolchain Availability Verification

All `6` `libFuzzer`-compatible harness files under [fuzz/fuzz_targets/](../fuzz/Cargo.toml) were inspected and preserved intact:
1. [fuzz_cell_decoder.rs](../fuzz/fuzz_targets/fuzz_cell_decoder.rs) (`Cell::decode/encode`, `RelayHopPlaintext::decode/encode`, `DecodedRequest::parse`)
2. [fuzz_frame_decoder.rs](../fuzz/fuzz_targets/fuzz_frame_decoder.rs) (`decode_wire_record`, `OuterFramePlaintext::unpack_link_frame`)
3. [fuzz_fragment_reassembly.rs](../fuzz/fuzz_targets/fuzz_fragment_reassembly.rs) (`InnerPayload::decode`, raw struct `MessageReassembler::push`)
4. [fuzz_http_response.rs](../fuzz/fuzz_targets/fuzz_http_response.rs) (`parse_sanitized_http_status`, `parse_http_health_response`, `parse_http_request_path`, `build_http_request_from_url`)
5. [fuzz_config_parser.rs](../fuzz/fuzz_targets/fuzz_config_parser.rs) (`RelayConfig`/`ClientConfigFile`/`DestServerConfig` TOML parsers & `decode_hex_32`)
6. [fuzz_noise_handshake.rs](../fuzz/fuzz_targets/fuzz_noise_handshake.rs) (`LinkInitiator`/`LinkResponder`, `HopHandshakeInitiator`/`HopHandshakeResponder`)

### Nightly `cargo-fuzz` & ASan Status (`BLOCKED`)
- `cargo fuzz` binary: **not installed** (`False`).
- `rustup toolchain list`: **only `stable-x86_64-pc-windows-msvc`** (`rustc 1.93.1`).
- `cargo check --manifest-path fuzz\Cargo.toml --offline`: failed (`error: no matching package named libfuzzer-sys found` — not in local Cargo cache).
- `cargo check --manifest-path fuzz\Cargo.toml` (non-offline sandbox check): blocked (`failed to download from https://index.crates.io/config.json: schannel: SEC_E_UNTRUSTED_ROOT`).
- **Honest Classification:** Coverage-guided LLVM libFuzzer + ASan instrumentation remains **`NOT VERIFIED` (`BLOCKED` in this offline Windows environment)**. Native compiled `--release` mutation fuzzing (`v02_fuzzer.rs`) does **not** substitute for ASan out-of-bounds/use-after-free checks or libFuzzer coverage guidance.

---

## 2. Extended Native Mutation Campaign (`v02_fuzzer.rs`, `VERIFIED OFFLINE`)

Executed after all `v0.3` code and seed additions (`target\release\examples\v02_fuzzer.exe 400000`, exit code `0`):

| Target | Adversarial Boundary Focus | Executions | Elapsed (`ms`) | Panics | Invariant Failures |
|---|---|---:|---:|---:|---:|
| `target_1_cell_and_hop_decoder` | Truncated headers, `RelayHopPlaintext` `< 571B` symmetry, bad `DestroyReason`, `CircuitId(0)`, `DecodedRequest` | `400,010` | `241` | `0` | `0` |
| `target_2_frame_and_wire_decoder` | `600B` wire prefix `0..u16::MAX`, `RekeyControl` epoch `0` / bad magic / wrong version | `400,005` | `152` | `0` | `0` |
| `target_3_fragment_reassembly` | Out-of-order / duplicate fragments, `chunk_count > 140`, `chunk_count = u16::MAX`, empty `ERROR` fragments | `400,012` | `197` | `0` | `0` |
| `target_4_http_response_and_url` | Control-byte/CRLF status stripping, malformed HTTP lines, userinfo/scheme/control URLs | `400,006` | `965` | `0` | `0` |
| `target_5_config_and_secret_parser` | Unclosed quotes, bad escapes, type mismatches & secret-canary non-leak checks across TOMLs, SSRF, CLI flags | `200,009` | `4,399` | `0` | `0` |
| `target_6_noise_handshake_inputs` | Truncated/corrupt `Noise_IK` & `Noise_NK` `msg1`/`msg2` state machines | `200,006` | `110,637` | `0` | `0` |
| **Total** | **6 Fuzz Targets (`v0.3` Post-Fix Extended Run)** | **`2,000,048`** | **`116,591`** | **`0`** | **`0`** |

---

## 3. Adversarial Cases, Defects Addressed & Allocation Bounds (`VERIFIED OFFLINE`)

1. **Bounded Configuration File & TOML Memory Protection (`v0.3` Hardening):**
   - *Gap Found:* Previously `RelayConfig::from_toml_str`, `ClientConfigFile::from_toml_str`, `RelayConfig::read_public_key_from_toml_str`, `DestServerConfig::from_toml_str`, and CLI config readers read/parsed arbitrarily huge TOML strings without an upfront size bound.
   - *Fix:* Enforced `MAX_CONFIG_TOML_BYTES = 512 * 1024` (`512 KiB`) both in [config.rs](../crates/network/src/config.rs) / [cli/src/lib.rs](../crates/cli/src/lib.rs) (via `read_bounded_toml_file` capping file reads with `File::take`) and `DestServerConfig::from_toml_str`.
2. **Adversarial Malformed TOML Secret-Canary Verification:**
   - Expanded [fuzz_config_tests.rs](../crates/network/tests/fuzz_config_tests.rs) and `v02_fuzzer.rs` `target_5` to fuzz unclosed strings (`private_key_hex = "<canary>\nbroken`), invalid string escapes (`\z`), unquoted values, table header injection (`[<canary>`), and inline comments on type errors (`private_key_hex = 12345 # <canary>`), verifying `0` secret-canary leaks.
   - Note: Verified `read_public_key_from_toml_str` parses `PublicOnly` cleanly when a valid TOML file also has unrelated malformed fields, ignoring `private_key_hex` altogether without reading it.
3. **Protocol Boundary, Control Cell, Fragment & DoS Allocation Regression Suites:**
   - Expanded [fuzz_property_tests.rs](../crates/protocol/tests/fuzz_property_tests.rs) (`adversarial_protocol_boundaries_control_cells_and_allocation_guards`, `5/5` tests passing): verifies `CircuitId(0)` / `RequestId(0)`, unknown `DestroyReason` (`0x08..0xFF`), `RekeyControl` epoch `0` & invalid version `0x99`, `chunk_count = 141` (`> MAX_CHUNKS_PER_MESSAGE`), duplicate/out-of-order chunks, and unvalidated `InnerPayload { chunk_index == chunk_count == 140 }` rejected **before** vector reservation.
   - Expanded [fuzz_http_tests.rs](../crates/cli/tests/fuzz_http_tests.rs): verifies `usize::MAX` `--data-bytes` CLI flag and `> 512 KiB` `DestServerConfig` fail cleanly without panic or OOM.
   - Preserved [fuzz_handshake_tests.rs](../crates/crypto/tests/fuzz_handshake_tests.rs) (`2/2` tests passing): exhaustive byte truncation (`0..len`) + bit-flips across `Noise_IK`/`Noise_NK` plus permanent session fail-closed verification.
   - Preserved [rekey_transport_tests.rs](../crates/network/tests/rekey_transport_tests.rs) & [network_tests.rs](../crates/network/tests/network_tests.rs): mid-frame cancellation session poisoning, unexpected EOF, bad length prefix, and `>4` consecutive rekey flood DoS rejection.
