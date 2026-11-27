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

## 4. Day 3 Rust Workspace & Multi-Process Demo Validation (`2026-11-27`)

| Command | Target | Observed Output | Status |
| :--- | :--- | :--- | :--- |
| `cargo fmt --all -- --check` | Full 6-crate workspace | Exit code `0` (no formatting diff) | **Passed** |
| `cargo clippy --offline --workspace --all-targets -- -D warnings` | Full 6-crate workspace + 6 binaries | Finished `dev` profile in `9.81s` (`0` warnings, exit `0`) | **Passed** |
| `cargo test --offline --workspace` | All 6 workspace crates | `40 passed; 0 failed; 0 ignored` | **Passed** |
| `powershell -ExecutionPolicy Bypass -File .\demo\run-demo.ps1 -AutoStartStop` | Live 5-process OS demo on Windows | `demo-dest`, `relay-exit`, `relay-middle`, `relay-entry`, `relay-client` passed all `10/10` scenarios + relay log proofs (`circuit_hops=10` each) + clean stop | **Passed** |

### Day 3 Tests Added Across Crates (`+11` Tests -> Total `40/40`)
- **`crates/crypto/tests/crypto_tests.rs` (`6 passed; 0 failed`):**
  - Added `static_keypair_rejects_mismatched_and_zero_keys`
  - Added `link_rekey_synchronization_boundary_simultaneous_and_fail_closed`
- **`crates/network/tests/network_tests.rs` (`5 passed; 0 failed`):**
  - Added `tcp_link_rekey_byte_limit_simultaneous_and_interrupted_failure`
  - Added `config_rejects_invalid_roles_mismatched_keys_loop_and_bounds`
- **`crates/relay/tests/relay_tests.rs` (`6 passed; 0 failed`):**
  - Added `entry_enforces_max_concurrent_connections_limit` (including `active_connection_count()` saturation and permit restoration)
  - Added `exit_enforces_destination_timeout_and_cleans_up_circuit` (`SEC-201` timeout & `active_circuit_count()` release)
- **`crates/client/tests/integration_tests.rs` (`10 passed; 0 failed`):**
  - Added `e2e_three_hop_survives_automatic_link_rekeys`
  - Added `e2e_redirect_response_is_not_followed_to_ssrf_target`
- **`crates/cli/tests/cli_tests.rs` (`3 passed; 0 failed`):**
  1. `cli_arg_parsing_and_url_validation_unit_checks` — Passed (flags, URL schemes/IPv6/userinfo rejection, `--data-bytes` limit)
  2. `cli_rejects_missing_config_wrong_role_and_bad_keys` — Passed (OS subprocess error exit checks + `--check-only`)
  3. `multi_process_os_three_hop_demo_and_failure_scenarios` — Passed (4 unique server/relay OS PIDs + client: `/health`, `0B`, `65_536B`, `/max-64kib`, `/redirect-ssrf`, `65_537B` reject, `/oversized` abort, `/slow` timeout, `PolicyDenied`, `ConnectFailed`, mid-flight Middle kill, plus verified `STATUS=READY`, `"relay node started"`, `"circuit hop established"` across Entry/Middle/Exit logs with zero leaked IPs/paths/bodies/keys)

### Live Windows PowerShell Demo Transcript Summary (`demo/run-demo.ps1 -AutoStartStop`)
- Ephemeral keygen (`demo/generated/`, gitignored) + 4 background OS processes (`demo-dest PID=39460`, `relay-exit PID=39500`, `relay-middle PID=45592`, `relay-entry PID=42288`) started and torn down cleanly via `stop-demo.ps1`.
- Executed scenarios `1..10`: empty `0B` (`137ms`), `/health` (`99ms`, `HTTP/1.1 200 OK`, `142B`), `/medium` (`168ms`, `12375B`), exact `65536B` raw (`675ms`, `65536B`), `/max-64kib` (`375ms`, `65536B`), `/redirect-ssrf` (`98ms`, `302 Found` unfollowed), `65537B` (`REJECTED_LOCALLY`, `81ms`), unlisted target `127.0.0.1:9099` (`PolicyDenied`, `89ms`), `/oversized` (`PayloadTooLarge`, `94ms`), and `/slow` (`Timeout`, `2601ms`).
- Multi-process log verification in `demo/logs/`: `relay-entry`, `relay-middle`, and `relay-exit` each recorded `STATUS=READY` and `circuit_hops=10` without logging IP addresses, target paths, payloads, or key hex values.

---

## 5. Deferred Post-`v0.1` Suites

| Suite | Target Phase | Status | Notes |
| :--- | :--- | :--- | :--- |
| Multi-host WAN soak benchmarks, Docker containers & K8s/Prometheus | Phase 6–8 | **Not Yet Executed / Deferred** | `dockerDesktopLinuxEngine` offline on host (`DEFERRED`); Kubernetes, Prometheus, and LLM integration excluded from Day 3 scope |
| Fuzzing (`cargo-fuzz`), `cargo-audit` & third-party security audit | Pre-Production | **Not Yet Executed** | `cargo-audit`/`cargo-deny` absent offline; required before any non-research deployment |
