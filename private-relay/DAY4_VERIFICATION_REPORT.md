# Day 4 Independent Engineering Verification Report — Private-Relay (`v0.1`)

> **Verification Date:** `2026-11-27`  
> **Baseline Audited Commit:** `cde0cbc26fc16c2329bf8ccecaa742f11482e3f8` (`origin/master` / `HEAD` at start of audit)  
> **Method:** Fresh source-line trace across all 6 crates (`protocol`, `crypto`, `network`, `relay`, `client`, `cli`), repository/remote inspection, live 5-process demo reproduction with OS PID/leak verification, and offline dependency/license/`unsafe` audit.  
> **Assurance Boundary:** Private-Relay `v0.1` remains an **experimental local prototype**. It is NOT externally audited, NOT production-hardened against global timing/correlation attacks, and lacks live CVE database scanning in this offline environment.

---

## 1. Per-Area Verification Classification

| # | Audited Claim / Component | Classification | Direct Evidence & Trace Notes |
| :--- | :--- | :--- | :--- |
| 1 | Repository HEAD, `origin/master` sync, and clean Day 3 diff (`45883c5..cde0cbc`) | **VERIFIED** | `git rev-parse HEAD` & `git ls-remote origin refs/heads/master` both returned `cde0cbc26fc16c2329bf8ccecaa742f11482e3f8`; `git diff --stat 45883c5..cde0cbc` (`48 files changed, 3961 insertions(+), 189 deletions(-)`) stayed strictly inside `private-relay/`. Unrelated directories (`relay-launch/`, `relay-site/`, `relay-web/`, `vexreach-web/`) remain untracked and unmodified. |
| 2 | Multi-process OS demo (`demo/run-demo.ps1 -AutoStartStop`), 5 OS processes, 10 scenarios, & zero leaked PIDs | **VERIFIED** | Reproduced cleanly: `PRE_PROCS=0`, spawned `demo-dest PID=34804`, `relay-exit PID=30072`, `relay-middle PID=42360`, `relay-entry PID=36612`, plus per-scenario `relay-client.exe` OS processes. All `10/10` scenarios passed; `relay-entry`/`relay-middle`/`relay-exit` logs confirmed `STATUS=READY` and `circuit_hops=10` each; `stop-demo.ps1` terminated all background PIDs (`POST_PROCS=0`, `POST_PIDFILE=False`). |
| 3 | `Noise_IK` Link Authentication, Framing (`600B`), & Fail-Closed Handling | **VERIFIED** | Traced [link.rs](./crates/crypto/src/link.rs) & [keys.rs](./crates/crypto/src/keys.rs): binds `b"private-relay-link-v1"`, verifies `rs == expected_remote_pub`, validates `X25519` public/private key match in `StaticKeypair::from_slices`, enforces `2B outer_len (598) + 582B plaintext + 16B MAC = 600B` via compile-time assertions in [constants.rs](./crates/protocol/src/constants.rs) & [frame.rs](./crates/protocol/src/frame.rs), and marks `LinkSession::failed = true` on AEAD/length/EOF errors. |
| 4 | `Noise_NK` Telescopic Setup, `HKDF-SHA256`, `ChaCha20-Poly1305`, `15B` AAD, Nonces & Replay/Exhaustion | **VERIFIED** | Traced [hop.rs](./crates/crypto/src/hop.rs) & [cell.rs](./crates/protocol/src/cell.rs): fresh per-hop ephemeral `Noise_NK` with `b"private-relay-hop-v1"`, transcript-salted `HKDF-SHA256` over `c_seed \|\| r_seed` (`D-08`), directional `fwd`/`bwd` `ChaCha20-Poly1305` keys in `Zeroizing<[u8; 32]>`, `[0,0,0,0] \|\| seq_be` nonces (`MAX_CIRCUIT_SEQ = 2^32`), `15B` AAD omitting link-local `CircuitId` (`D-07`), and strict `incoming_seq == expected_seq` FIFO replay checks. |
| 5 | Request/Response Chunking, Circuit Lifecycle & Exit Replay Window (`D-01`) | **VERIFIED (Improved in Audit)** | Traced [message.rs](./crates/protocol/src/message.rs), [circuit.rs](./crates/protocol/src/circuit.rs), & [engine.rs](./crates/relay/src/engine.rs): `<= 65_536B` body + `<= 255B` target fit `<= 140` chunks (`136` max), `CircuitId(0)` rejected, `0x8000_0000` MSB prevents link collisions. Audit finding **`D4-02`** replaced full `used_request_ids.clear()` at `4096` with a bounded sliding FIFO eviction window (`VecDeque`). |
| 6 | Key Hygiene & Teardown Zeroization | **VERIFIED** | `StaticKeypair`, `HopCipherState`, `HopCipherPair`, and `ClientCircuitCrypto` derive/implement `ZeroizeOnDrop`; intermediate seeds/keys/padding buffers are explicitly wrapped in `Zeroizing` or zeroized immediately. *(Note: `snow::TransportState` internal cipher keys rely on `snow` drop semantics rather than user-callable `ZeroizeOnDrop`.)* |
| 7 | Exit SSRF Protection, DNS TOCTOU, Redirects & Timeout Budget | **PARTIALLY VERIFIED -> FIXED & VERIFIED** | Audit caught **`D4-01`** in [policy.rs](./crates/network/src/policy.rs): `validate_ipv6` previously checked `to_ipv4_mapped()` (`::ffff:0:0/96`) only, allowing IPv4-compatible IPv6 (`::/96` such as `::127.0.0.1`, `::169.254.169.254`), `fec0::/10`, `0100::/64`, `2001::/32`, `2002::/16`, `::ffff:0:0:0/96`, and `%` zone IDs. Fixed and verified via new tests in [network_tests.rs](./crates/network/tests/network_tests.rs). DNS resolution still picks `resolved[0]` (`SEC-205`), validates all returned IPs once, connects directly to `validated_addr: SocketAddr` under a single combined `timeout(dest_timeout, ...)` (`D4-02`), and never follows HTTP `3xx` redirects. |
| 8 | `KI-08` Automatic Noise Link Rekeying (`D-09`) | **PARTIALLY VERIFIED (Mechanism Verified; Long Soak Unrun)** | Traced [link.rs](./crates/crypto/src/link.rs), [transport.rs](./crates/network/src/transport.rs), [engine.rs](./crates/relay/src/engine.rs), & [client.rs](./crates/client/src/client.rs): automatic `REKEY(k)` via `snow::TransportState::rekey_outgoing`/`rekey_incoming` **is implemented** with monotonic nonces (`n -> n+1`, never reset) and coordinated `RekeyControl { epoch }` frames (`0xFFFF \|\| b"PR_REKEY"`), wired in both relays and client. Triggering is pre-send (`LinkWriter::send_cell` checking `1 GiB` / `3600s` / `2^48` nonce), tested via lowered thresholds (`1200B`, explicit triggers, mid-frame EOF, `>4` consecutive rekey flood); multi-hour / `1 GiB` continuous WAN soaks remain unexecuted. |
| 9 | Dependency License/Tree Inventory & First-Party `unsafe` Scan | **VERIFIED (Local)** | `rg -n 'unsafe' private-relay\crates\` found **`0` occurrences** across all 6 workspace crates. `cargo tree --offline --workspace --format '{p} {l}'` & `--duplicates` confirmed permissive licenses (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `Unicode-3.0`), pure-Rust crypto without OpenSSL/ring C FFI, and only proc-macro build duplicate `syn` (`2.0.119` & `3.0.10`). |
| 10 | Automated Dependency CVE Advisory Scanning (`cargo-audit` / `cargo-deny` / `osv-scanner`) | **NOT VERIFIED** | Confirmed `cargo-audit`, `cargo-deny`, `osv-scanner`, `pip-audit`, `trivy`, and local `%USERPROFILE%\.cargo\advisory-db` are all absent offline. No CVE database match was executed. |

---

## 2. Newly Discovered Findings During Day 4 Audit & Fixes Applied

### `[D4-01]` IPv6 Transition/Embedded SSRF Bypasses (`::/96`, `2002::/16`, `fec0::/10`, Zone IDs) — **Medium (Fixed & Regression Tested)**
- **Location:** [crates/network/src/policy.rs](./crates/network/src/policy.rs) (`DestinationPolicy::validate_ipv6`, `resolve_and_validate`).
- **Vulnerability:** `validate_ipv6` previously used `ip.to_ipv4_mapped()` instead of `ip.to_ipv4()`, so deprecated IPv4-compatible IPv6 addresses (`::127.0.0.1`, `::10.0.0.1`, `::169.254.169.254`) returned `None` and bypassed all IPv4 SSRF checks (`Ok(())`). Deprecated site-local (`fec0::/10`), discard (`0100::/64`), Teredo (`2001::/32`), benchmarking (`2001:2::/48`), SIIT IPv4-translated (`::ffff:0:0:0/96`), 6to4 (`2002::/16`), and `%` IPv6 zone IDs (`[fe80::1%eth0]:80`) were also unblocked.
- **Remediation:** Rejected `'%'` in `resolve_and_validate`; switched non-unspecified/non-loopback embedded IPv4 checks to `ip.to_ipv4()` (covering both `::ffff:0:0/96` and `::/96`); and explicitly blocked `0100::/64`, `2001::/32`, `2001:2::/48`, `2002::/16`, `fec0::/10`, and `::ffff:0:0:0/96`.
- **Verification:** Expanded `ssrf_policy_blocks_private_and_loopback_by_default` in [crates/network/tests/network_tests.rs](./crates/network/tests/network_tests.rs) to assert denial across all added IPv6/zone-ID vectors (`network` `5/5` passed).

### `[D4-02]` Exit Sliding Replay Window & Total Destination Deadline Budget — **Low (Hardened)**
- **Location:** [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) (`run_exit_circuit_task`, `execute_destination_request`).
- **Issue:** `used_request_ids.clear()` discarded all prior request IDs at count `4096` instead of sliding eviction, and `execute_destination_request` allowed 3 separate `timeout(dest_timeout, ...)` budgets (`DNS + connect + write/read` up to `3 * dest_timeout`).
- **Remediation:** Added `VecDeque<u32>` sliding FIFO eviction at capacity `4096` and consolidated DNS resolution, `TcpStream::connect`, write, and bounded read inside one `timeout(dest_timeout, ...)` guard.
- **Verification:** Verified via `exit_enforces_destination_timeout_and_cleans_up_circuit`, full `relay` (`6/6`) / `client` (`10/10`) / `cli` (`3/3`) test suites, and Scenario `10` (`/slow`, `2610ms`) in `demo/run-demo.ps1`.

---

## 3. Observed Command Outputs (Post-Fix Verification Run)

- **`cargo fmt --all -- --check`:** Exit `0`
- **`cargo clippy --offline --workspace --all-targets -- -D warnings`:** Exit `0` (`0` warnings)
- **`cargo test --offline --workspace`:** Exit `0` (**40 passed; 0 failed; 0 ignored** — `3` CLI, `10` Client E2E, `6` Crypto, `5` Network, `10` Protocol, `6` Relay)
- **`powershell -ExecutionPolicy Bypass -File .\demo\run-demo.ps1 -AutoStartStop`:** Exit `0` (`demo-dest PID=34804`, `relay-exit PID=30072`, `relay-middle PID=42360`, `relay-entry PID=36612`; `10/10` cases passed; `relay-{entry,middle,exit}` logs `circuit_hops=10`; `PRE_PROCS=0`, `POST_PROCS=0`, `POST_PIDFILE=False`).

---

## 4. Readiness Conclusion Before Docker / Kubernetes / LLM Stages

- **Core 3-hop protocol, crypto, CLI, SSRF boundary, and local Windows multi-process runtime:** **Solid & Verified (`40/40` tests + clean 5-process run + `D4-01`/`D4-02` remediated).**
- **Before any external exposure or Docker/K8s rollout:** Perform an external `cargo-audit` CVE check once connected to an advisory database, add dedicated multi-hour link-rekey soak benchmarks, and keep `allow_loopback_for_test` strictly `false` outside local demos.
