# Test & Verification Results (`TEST_RESULTS.md`)

> **Verification Standard:** Only tests and environment checks actually executed locally are recorded here. Unrun tests are explicitly marked as *Not Yet Executed*.

---

## 1. Environment & Toolchain Checks Executed

| Check | Date | Environment | Command | Observed Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Rust compiler & Cargo | `2026-11-26` | Windows PowerShell | `rustc --version; cargo --version` | `rustc 1.93.1 (01f6ddf75 2026-02-11)` / `cargo 1.93.1 (083ac5135 2025-12-15)` | **Verified** |
| Active toolchain & MSVC linker | `2026-11-26` | Windows PowerShell | `rustup toolchain list` + VS2022 `link.exe` lookup | `stable-x86_64-pc-windows-msvc (active, default)` + MSVC `14.44.35207` `link.exe` present | **Verified** |

---

## 2. Day 1 Rust Workspace Validation (`2026-11-26`)

| Command | Target | Observed Output | Status |
| :--- | :--- | :--- | :--- |
| `cargo fmt --all -- --check` | Workspace (`crates/protocol`) | Exit code `0` (no formatting diff) | **Passed** |
| `cargo check --workspace` | `private-relay-protocol v0.1.0` | `Finished dev profile in 1.77s` | **Passed** |
| `cargo test --workspace` | `crates/protocol/tests/protocol_tests.rs` | `running 10 tests ... test result: ok. 10 passed; 0 failed; 0 ignored` | **Passed** |
| `cargo clippy --workspace --all-targets -- -D warnings` | Workspace (`--all-targets`) | `Finished dev profile in 2.55s` (0 warnings, exit `0`) | **Passed** |

### Day 1 Test Cases Executed (`crates/protocol/tests/protocol_tests.rs`)
1. `t01_t02_t03_valid_cell_encode_decode_and_roundtrips` — Passed (`Create`, `Created`, `RelayData`, `Destroy`)
2. `t03_relay_hop_plaintext_roundtrips` — Passed (`Forward`, `Extend`, `Message`, `Extended`)
3. `t04_t05_fixed_size_frame_and_padding_invariance` — Passed (`600B` wire record, `582B` outer plaintext, non-zero caller padding, insufficient padding rejected)
4. `t06_invalid_frame_lengths_rejected` — Passed (`outer_len != 598`, wrong wire/plaintext lengths, invalid `real_len`)
5. `t07_truncated_messages_rejected` — Passed (truncated cell header, body mismatch, truncated inner/request headers)
6. `t08_oversized_messages_rejected` — Passed (`body > 571B`, logical request/response `> 64 KiB`, `fragment > 487B`, reassembler limit)
7. `t09_maximum_permitted_logical_request_and_response_roundtrip` — Passed (`65,536B` body + `255B` target in `136 <= 140` chunks)
8. `t10_t11_t12_chunk_ordering_missing_duplicate_and_count_validation` — Passed (chunk count bounds, duplicate/missing/out-of-order rejection, illegal flags, error cell)
9. `t13_t14_invalid_request_circuit_ids_and_protocol_versions` — Passed (`CircuitId(0)`, `RequestId(0)`, ID mismatch, unsupported versions `0x00`/`0x02`)
10. `t15_circuit_and_request_state_transitions_and_aad_invariance` — Passed (`CircuitState`, `RequestState`, canonical 15B `build_hop_aead_aad`)

---

## 3. Day 2 Rust Workspace Validation (`2026-11-26`)

| Command | Target | Observed Output | Status |
| :--- | :--- | :--- | :--- |
| `cargo fmt --all -- --check` | Full 5-crate workspace (`protocol`, `crypto`, `network`, `relay`, `client`) | Exit code `0` (no formatting diff) | **Passed** |
| `cargo clippy --offline --workspace --all-targets -- -D warnings` | Full 5-crate workspace (`--all-targets`) | Finished `dev` profile in `5.94s` (later full build step `11.32s`, `0` warnings, exit `0`) | **Passed** |
| `cargo test --offline --workspace` | All 5 workspace crates | `29 passed; 0 failed; 0 ignored` (unit + integration) | **Passed** |

### Day 2 Test Cases Executed Across Newly Implemented Crates
- **`crates/crypto/tests/crypto_tests.rs` (`4 passed; 0 failed`):**
  1. `link_ik_handshake_authentication_and_frame_sealing` — Passed (`Noise_IK` auth, `600B` frame seal/open)
  2. `hop_nk_handshake_rejects_spoofed_identity_and_bad_messages` — Passed (`Noise_NK` pubkey pin & corrupt msg rejection)
  3. `three_hop_layered_onion_forward_and_backward_roundtrip` — Passed (`1..=3` telescopic forward/backward onion wrapping)
  4. `aead_tamper_wrong_key_aad_metadata_replay_and_exhaustion` — Passed (bitflip tamper, replay, FIFO gap, sequence cap)
- **`crates/network/tests/network_tests.rs` (`3 passed; 0 failed`):**
  1. `ssrf_policy_blocks_private_and_loopback_by_default` — Passed (private, CGNAT, loopback, link-local, test override)
  2. `partial_tcp_reads_writes_and_multiple_frames_over_noise_link` — Passed (`TrickleStream` partial read/write framing)
  3. `tcp_link_rejects_bad_prefix_truncated_eof_and_bad_auth` — Passed (wrong remote key, EOF truncation, bad `!= 598` prefix, TOML serde)
- **`crates/relay/tests/relay_tests.rs` (`4 passed; 0 failed`):**
  1. `entry_rejects_early_relay_data_and_message_payload` — Passed (`DestroyReason::ProtocolError`)
  2. `entry_rejects_unauthorized_middle_peer` — Passed (`DestroyReason::PolicyDenied`)
  3. `entry_enforces_max_concurrent_circuits_capacity` — Passed (`DestroyReason::ResourceLimit`)
  4. `exit_enforces_ssrf_and_handles_direct_valid_request` — Passed (`RequestErrorCode::PolicyDenied`)
- **`crates/client/tests/integration_tests.rs` (`8 passed; 0 failed` — Full 3-Relay Local TCP + Controlled Destination):**
  1. `e2e_three_hop_empty_small_and_exact_64kib_requests_succeed` — Passed (`0B`, ASCII, and `65_536B` max roundtrip across `Entry→Middle→Exit→Dest` + clean teardown)
  2. `e2e_ssrf_and_destination_connect_errors_propagate_without_crashing_circuit` — Passed (`PolicyDenied` & `ConnectFailed`, followed by surviving healthy request)
  3. `e2e_oversized_request_and_oversized_response_are_enforced` — Passed (`65_537B` client reject & `PayloadTooLarge` on `> 64 KiB` dest response)
  4. `e2e_slow_destination_triggers_exit_timeout_code` — Passed (`RequestErrorCode::Timeout` on stalled destination)
  5. `e2e_relay_unavailable_and_wrong_pubkey_fail_cleanly` — Passed (wrong Entry key rejected; dead Middle aborts & frees Entry slot via cancellation-safe dial)
  6. `e2e_middle_shutdown_mid_circuit_propagates_destroy_and_cleans_up` — Passed (abrupt Middle shutdown propagates cleanup to `0` active circuits on Entry & Exit)
  7. `e2e_tampered_frame_or_hop_ciphertext_destroys_circuit` — Passed (hop AEAD bitflip -> `CryptoFail`; wire TCP proxy bitflip -> link rejected)
  8. `tracing_logs_never_contain_ips_destinations_keys_or_payloads` — Passed (global subscriber verified zero `127.0.0.1`, target host:port, pubkeys, or payload leaked)

---

## 4. Remaining Day 3 Suites

| Suite | Target Day | Status | Notes |
| :--- | :--- | :--- | :--- |
| CLI binary runner & reproducible local 3-relay demo walkthrough | Day 3 | **Not Yet Executed** | Planned for Day 3 integration & release |
| Sustained multi-circuit concurrency / backpressure / slowloris soak tests | Day 3 | **Not Yet Executed** | Planned for Day 3 reliability validation |
