# Security Review Report — Private-Relay (`v0.1`)

> **Date:** `2026-11-27`  
> **Scope:** Focused engineering code review and live adversarial verification across `crates/protocol`, `crates/crypto`, `crates/network`, `crates/relay`, `crates/client`, `crates/cli`, and `demo/`.  
> **Dependency Tooling Note:** `cargo-audit` and `cargo-deny` are NOT installed in this offline Windows workspace; dependency hygiene relies on inspecting `Cargo.lock` (pure-Rust `snow 0.9.6`, `chacha20poly1305 0.10.1`, `hkdf 0.12.4`, `blake2 0.10.6`, `curve25519-dalek 4.1.3`, `zeroize`) rather than automated CVE advisory matching.  
> **Important Notice:** This is an internal engineering security review. **Private-Relay v0.1 is NOT production-ready, NOT production-secure, and does NOT claim global anonymity or resistance to passive timing/volume traffic analysis.** Independent external cryptographic and penetration audits have NOT been performed.

---

## 1. Component Verification Summary (16-Point Check)

| # | Area | Implementation File(s) Reviewed | Findings & Verification Status |
| :--- | :--- | :--- | :--- |
| 1 | **`Noise_IK` Link Authentication** | [crates/crypto/src/link.rs](./crates/crypto/src/link.rs), [crates/crypto/src/keys.rs](./crates/crypto/src/keys.rs), [crates/network/src/transport.rs](./crates/network/src/transport.rs) | **Verified:** Binds prologue `b"private-relay-link-v1"`, requires `remote_static_pub == expected_remote_pub`, rejects wrong server keys during handshake, and enforces keypair mathematical consistency (`SEC-203`). |
| 2 | **`Noise_NK` Telescopic Hops** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs) | **Verified:** Client initiator sends zero static key (`N`), responder pins relay static `X25519` key (`K`), binds `b"private-relay-hop-v1"`, blocking Entry MITM against Middle. |
| 3 | **`HKDF-SHA256` Key Derivation** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs) | **Verified (`D-08`):** Uses Noise `get_handshake_hash()` as HKDF salt over encrypted `c_seed \|\| r_seed` (`es` / `es, ee`), deriving separated directional keys (`fwd` / `bwd`) in `Zeroizing<[u8; 32]>`. |
| 4 | **`ChaCha20-Poly1305` Nonces & Rekey** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs), [crates/crypto/src/link.rs](./crates/crypto/src/link.rs) | **Verified (`D-09`):** Hop AEAD builds 96-bit nonce `[0,0,0,0] \|\| seq_be` (`seq < 2^32`). Link transport calls `snow::TransportState::rekey_outgoing`/`rekey_incoming` (`3600s` / `1 GiB` defaults) without resetting monotonic nonces. |
| 5 | **15-Byte AEAD AAD (`D-07`)** | [crates/protocol/src/cell.rs](./crates/protocol/src/cell.rs) | **Verified:** Binds `b"PRv1" \|\| version \|\| direction \|\| hop_index \|\| seq` (`15B`), omitting link-local `CircuitId` while binding direction and hop index (`aead_tamper_wrong_key_aad_metadata_replay_and_exhaustion`). |
| 6 | **FIFO Sequencing & Replay Protection** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs), [crates/crypto/src/link.rs](./crates/crypto/src/link.rs) | **Verified:** `RELAY_DATA` requires `seq == expected_seq`; gaps/replays fail decryption and emit `DestroyReason::CryptoFail`. Rekey frames enforce `epoch == incoming_rekey_epoch + 1` and poison `LinkSession` on any failure (`failed = true`). |
| 7 | **Fixed `600`-Byte Link Framing (`D-02`)** | [crates/protocol/src/frame.rs](./crates/protocol/src/frame.rs) | **Verified:** Compile-time assertions enforce `2B outer_len (598) + 582B plaintext + 16B MAC = 600B`; filler uses `OsRng`; link rekey control frames (`0xFFFF \|\| b"PR_REKEY"`) share exact `600`-byte wire sizing. |
| 8 | **`CircuitId` Handling** | [crates/protocol/src/circuit.rs](./crates/protocol/src/circuit.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | **Verified:** Rejects `CircuitId(0)`; MSB initiator parity bit (`0x8000_0000`) prevents link allocation collisions; identifiers remain link-local (`C1`, `C2`, `C3`). |
| 9 | **Request Chunking & Reassembly** | [crates/protocol/src/message.rs](./crates/protocol/src/message.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | **Verified (`D-01`):** Enforces `<= 65_536B` logical payload, `<= 255B` target, `<= 140` chunks, single active request per circuit, and Exit `used_request_ids` replay rejection. |
| 10 | **Exit SSRF Protections** | [crates/network/src/policy.rs](./crates/network/src/policy.rs) | **Verified:** `allow_loopback_for_test` defaults to `false`; blocks RFC1918, `0.0.0.0/8`, loopback, `169.254.0.0/16`, `100.64.0.0/10`, `198.18.0.0/15`, multicast/`>=240.0.0.0`, IPv6 `::/128`, `::1`, `fe80::/10`, `fc00::/7`, `ff00::/8`, NAT64 `64:ff9b::/96`, and `::ffff:0:0/96` (`SEC-204`). |
| 11 | **DNS Resolution, Timeout & TOCTOU** | [crates/network/src/policy.rs](./crates/network/src/policy.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | **Verified:** Client never resolves DNS (`--url` sends hostname verbatim). Exit calls `lookup_host` once under `timeout(dest_timeout, ...)` (`SEC-201`), validates every returned IP, and connects directly to `validated_addr: SocketAddr`. |
| 12 | **HTTP Redirect Behavior** | [crates/cli/src/lib.rs](./crates/cli/src/lib.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | **Verified:** Neither Exit nor `relay-client` parses or follows HTTP `3xx Location` headers (`302 Location: http://169.254.169.254/...` returns passively once). |
| 13 | **IPv4 & IPv6 Policy Parity** | [crates/network/src/policy.rs](./crates/network/src/policy.rs) | **Verified:** IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`) delegate cleanly to `validate_ipv4`; ULA, link-local, loopback, and NAT64 tested. |
| 14 | **Resource Exhaustion Defenses** | [crates/relay/src/engine.rs](./crates/relay/src/engine.rs), [crates/network/src/transport.rs](./crates/network/src/transport.rs) | **Verified:** `max_concurrent_connections` semaphore (`256`, `SEC-202`), `max_concurrent_circuits` (`1024`), Entry `max_circuits_per_peer_ip` (`16`), `mpsc(64)`, `MAX_CONSECUTIVE_REKEYS = 4`, bounded timeouts, `120s` TTL, and `64 KiB` dest read cap. |
| 15 | **Logging & Secret Redaction** | [crates/relay/src/engine.rs](./crates/relay/src/engine.rs), [crates/cli/src/lib.rs](./crates/cli/src/lib.rs) | **Verified:** Custom `Debug` redaction and structured `tracing` omit IPs, targets, keys, and payloads (`tracing_logs_never_contain_ips_destinations_keys_or_payloads` + `multi_process_os_three_hop_demo_and_failure_scenarios`). |
| 16 | **Key Lifecycle & Cleanup** | [crates/crypto/src/keys.rs](./crates/crypto/src/keys.rs), [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs) | **Verified:** `StaticKeypair`, `HopCipherState`, `HopCipherPair`, and `ClientCircuitCrypto` implement `ZeroizeOnDrop`; intermediate seeds use `Zeroizing` / `.zeroize()`; torn circuits release `CircuitSlotGuard` and connection permits cleanly. |

---

## 2. Classified Security Findings (`Critical` / `High` / `Medium` / `Low` / `Informational`)

*(No unresolved `Critical` implementation vulnerabilities were identified inside the `v0.1` workspace scope.)*

### `[SEC-201]` Unbounded DNS Lookup Duration at Exit — **Medium (Remediated)**
- **Location:** `crates/relay/src/engine.rs` (`execute_destination_request`), `crates/network/src/policy.rs` (`DestinationPolicy::resolve_and_validate`).
- **Impact:** Previously, Exit applied `timeout(dest_timeout, ...)` to `TcpStream::connect` and stream read/write, but awaited `policy.resolve_and_validate(&req.target_host_port)` without a timeout wrapper. A slow or stalled DNS resolver could hold an Exit circuit task blocked beyond `destination_io_timeout_ms`.
- **Reproduction:** Send a request targeting a hostname or stalled destination path where host resolution / connect exceeds `destination_io_timeout_ms`.
- **Fix:** Wrapped `policy.resolve_and_validate(&req.target_host_port)` inside `timeout(dest_timeout, ...)` in `execute_destination_request`, returning `RequestErrorCode::Timeout` on expiration before freeing the circuit cleanly.
- **Verification:** Verified via `exit_enforces_destination_timeout_and_cleans_up_circuit` (`crates/relay/tests/relay_tests.rs`), `e2e_slow_destination_triggers_exit_timeout_code` (`crates/client/tests/integration_tests.rs`), and Case `10` (`/slow`) in `demo/run-demo.ps1`.

### `[SEC-202]` Unbounded Pre-Handshake TCP Accept Concurrency — **Medium (Remediated)**
- **Location:** `crates/relay/src/engine.rs` (`RelayServer::start`, `conn_semaphore`), `crates/network/src/config.rs` (`max_concurrent_connections`).
- **Impact:** Prior to Day 3 hardening, a relay accepted unlimited concurrent TCP sockets and spawned `Noise_IK` handshake tasks prior to circuit admission checks, allowing connection/handshake exhaustion.
- **Reproduction:** Hold `max_concurrent_connections` concurrent Noise links open and attempt an additional connection to `Entry`.
- **Fix:** Added an accept-time `Arc<Semaphore>` (`default = 256`) using non-blocking `try_acquire_owned()`, immediately dropping excess accepted TCP sockets before any Noise handshake work, and exposed `RelayHandle::active_connection_count()` for verification.
- **Verification:** Verified via `entry_enforces_max_concurrent_connections_limit` (`crates/relay/tests/relay_tests.rs`), confirming socket rejection when saturated and permit release back to `0` on disconnect.

### `[SEC-203]` Unvalidated Static X25519 Keypair Mismatches in TOML Configuration — **Medium (Remediated)**
- **Location:** `crates/crypto/src/keys.rs` (`StaticKeypair::from_slices`), `crates/network/src/config.rs` (`RelayConfig::validate`).
- **Impact:** Loading an operator-edited config whose `public_key_hex` does not match `X25519(private_key_hex)` (or contains all-zero bytes) would silently boot a node that fails all incoming/outgoing `Noise_IK` / `Noise_NK` handshakes.
- **Reproduction:** Configure a relay TOML with mismatched `public_key_hex` and `private_key_hex` or all-zero bytes and invoke `RelayConfig::from_toml_str` / `relay-entry --check-only`.
- **Fix:** Enforced mathematical `X25519` public/private key consistency and all-zero rejection in `StaticKeypair::from_slices` and validated peer-role topology / zero-bound caps in `RelayConfig::validate` and `ClientConfigFile::validate`.
- **Verification:** Verified via `static_keypair_rejects_mismatched_and_zero_keys` (`crates/crypto/tests/crypto_tests.rs`), `config_rejects_invalid_roles_mismatched_keys_loop_and_bounds` (`crates/network/tests/network_tests.rs`), and `cli_rejects_missing_config_wrong_role_and_bad_keys` (`crates/cli/tests/cli_tests.rs`).

### `[SEC-204]` Missing IPv4 `0.0.0.0/8` & IPv6 NAT64 (`64:ff9b::/96`) SSRF Filters — **Low (Remediated)**
- **Location:** `crates/network/src/policy.rs` (`DestinationPolicy::validate_ipv4`, `validate_ipv6`).
- **Impact:** Incomplete reserved-range checks could allow outbound Exit dialing toward IPv4 `0.0.0.0/8` ("this network"), benchmarking (`198.18.0.0/15`), IETF protocol (`192.0.0.0/24`), or IPv6 NAT64 translation (`64:ff9b::/96`) addresses.
- **Reproduction:** Validate `0.10.0.1` or `64:ff9b::127.0.0.1` against `DestinationPolicy::validate_ip`.
- **Fix:** Explicitly denied `0.0.0.0/8`, `198.18.0.0/15`, `192.0.0.0/24`, `64:ff9b::/96`, documentation ranges, RFC1918, CGNAT, link-local, loopback (default `false`), ULA, multicast, and `::ffff:0:0/96` IPv4-mapped addresses.
- **Verification:** Verified via `ssrf_policy_blocks_private_and_loopback_by_default` (`crates/network/tests/network_tests.rs`).

### `[SEC-205]` Single-Address Selection (`resolved[0]`) & OS Resolver Trust — **Low (Accepted `v0.1` Boundary)**
- **Location:** `crates/network/src/policy.rs` (`DestinationPolicy::resolve_and_validate`).
- **Impact:** After validating **all** addresses returned by `lookup_host(target)`, Exit dials only `resolved[0]` without multi-address fallback (`resolved[1..]`) and trusts the Exit host OS resolver to resolve public domains honestly when `allowed_targets` is left empty.
- **Reproduction:** Query a multi-A/AAAA domain where `resolved[0]` is unreachable, or configure a compromised local DNS resolver on the Exit host.
- **Fix / Mitigation:** Accepted for `v0.1` local prototype simplicity; operator deployments should restrict `allowed_targets` explicitly. Multi-address failover and dedicated DNS transport are deferred beyond `v0.1`.
- **Verification:** Direct code inspection confirms single-resolution `resolved[0]` handoff (`TcpStream::connect(validated_addr)`).

### `[KI-01]` Dual-Ended Passive Traffic Correlation — **High (Informational Architectural Limit)**
- **Location:** Network/protocol architecture ([THREAT_MODEL.md](./THREAT_MODEL.md), `crates/protocol/src/frame.rs`).
- **Impact:** An adversary observing both `Client <-> Entry` and `Exit <-> Destination` can correlate request timestamps and cell burst counts despite 3-hop encryption and `600`-byte link frames.
- **Reproduction:** Compare ingress packet bursts at Entry against egress bursts at Exit on an idle testbed.
- **Fix / Mitigation:** Not mitigated in `v0.1`; requires mix-net batching or cover traffic beyond `v0.1`.
- **Verification:** Explicitly documented as out-of-scope in [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) and [SECURITY_DESIGN.md](./SECURITY_DESIGN.md).

### `[KI-02]` Colluding `Entry + Exit` or Sybil Relays — **High (Informational Architectural Limit)**
- **Location:** Topology / static descriptor configuration (`crates/network/src/config.rs`, [THREAT_MODEL.md](./THREAT_MODEL.md)).
- **Impact:** If the same operator controls both `Entry` and `Exit` (or no Coordinator directory diversity rules exist), sender IP and destination address can be correlated.
- **Reproduction:** Configure `client.toml` pointing `Entry` and `Exit` to relays operated by one entity.
- **Fix / Mitigation:** Deferred to Phase 5/6 Coordinator operator-ID and `/24`/`/48` prefix diversity enforcement.
- **Verification:** Explicitly documented in [KNOWN_ISSUES.md](./KNOWN_ISSUES.md).

### `[KI-03]` Fixed-Role Hop-Depth Length Leakage Inside `582B` Outer Plaintext — **Medium (Informational Design Trade-off)**
- **Location:** `crates/protocol/src/cell.rs`, `crates/crypto/src/hop.rs`.
- **Impact:** Each nested `ChaCha20-Poly1305` onion layer strips `25B` (`1B subcmd + 8B seq + 16B tag`) within the `571B` max cell body (`582B` outer plaintext), allowing an honest relay to observe whether it sits at hop `1`, `2`, or `3` if unpadded internally.
- **Reproduction:** Inspect decrypted `RelayHopPlaintext` payload length across `Entry -> Middle -> Exit`.
- **Fix / Mitigation:** Accepted trade-off for fixed 3-role `Entry -> Middle -> Exit` topology (`v0.1`); Sphinx constant-size headers are out of scope beyond `v0.1`.
- **Verification:** Documented in [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) and [PROTOCOL_SPEC.md](./PROTOCOL_SPEC.md).

### `[D4-01]` IPv6 Transition/Embedded SSRF Bypasses (`::/96`, `2002::/16`, `fec0::/10`, Zone IDs) — **Medium (Fixed in Day 4 Audit)**
- **Location:** `crates/network/src/policy.rs` (`DestinationPolicy::validate_ipv6`, `resolve_and_validate`).
- **Impact:** Checking only `ip.to_ipv4_mapped()` allowed deprecated IPv4-compatible IPv6 (`::127.0.0.1`, `::10.0.0.1`, `::169.254.169.254`) plus `fec0::/10`, `0100::/64`, `2001::/32`, `2002::/16`, `::ffff:0:0:0/96`, and `%` IPv6 zone IDs to bypass default SSRF filters when `allowed_targets` was empty.
- **Reproduction:** Pass `[::127.0.0.1]:80` or `[::169.254.169.254]:80` to `DestinationPolicy::validate_ip`, or `[fe80::1%eth0]:80` to `resolve_and_validate`.
- **Fix:** Rejected `'%'` in `resolve_and_validate`; switched non-unspecified/non-loopback checks to `ip.to_ipv4()` (covering `::ffff:0:0/96` and `::/96`); blocked `0100::/64`, `2001::/32`, `2001:2::/48`, `2002::/16`, `fec0::/10`, and `::ffff:0:0:0/96`.
- **Verification:** Expanded `ssrf_policy_blocks_private_and_loopback_by_default` (`crates/network/tests/network_tests.rs`, `5/5` passed) and documented full audit in [DAY4_VERIFICATION_REPORT.md](./DAY4_VERIFICATION_REPORT.md).

### `[D4-02]` Exit Sliding Replay Window & Total Destination Deadline — **Low (Hardened in Day 4 Audit)**
- **Location:** `crates/relay/src/engine.rs` (`run_exit_circuit_task`, `execute_destination_request`).
- **Impact:** Clearing `used_request_ids` at capacity `4096` wiped recent history, and 3 separate timeouts (`DNS + connect + write/read`) allowed up to `3 * dest_timeout` cumulative wait.
- **Remediation:** Replaced full clear with bounded FIFO sliding eviction (`VecDeque<u32>`) and enforced a single cumulative `timeout(dest_timeout, ...)` across DNS resolution, connect, write, and read.
- **Verification:** Verified via `exit_enforces_destination_timeout_and_cleans_up_circuit` (`6/6` relay tests) and live `demo/run-demo.ps1 -AutoStartStop` (`/slow`, `2610ms`).

### `[KI-09]` Unverified Third-Party Audit, Fuzzing & Offline Dependency Scanner Gaps — **Informational (Pre-Production Gate)**
- **Location:** Workspace build & verification scope (`Cargo.lock`, [TEST_RESULTS.md](./TEST_RESULTS.md)).
- **Impact:** `cargo-fuzz`, `cargo-audit`, `cargo-deny`, external cryptographic review, and WAN container/multi-host soak tests have NOT been executed.
- **Reproduction:** Run `cargo-audit` in this environment (`cargo-audit`, `cargo-deny`, `osv-scanner`, and local `advisory-db` absent).
- **Fix / Mitigation:** Maintain strict research-prototype classification until independent audit, fuzzing, and CVE advisory scanning complete.
- **Verification:** Offline `cargo tree` / license inventory and `0`-match `unsafe` scan across `crates/` verified cleanly in [DAY4_VERIFICATION_REPORT.md](./DAY4_VERIFICATION_REPORT.md); all `40/40` workspace tests pass.

---

## 3. Honest Assurance Classification

- **Verified Implementation Properties (Localhost OS & Workspace Tests):**
  - 3-hop `Client -> Entry -> Middle -> Exit -> Destination` encrypted forwarding across 5 distinct Windows OS processes with verified `STATUS=READY`, `"relay node started"`, and `"circuit hop established"` logs and zero IP/key/payload leaks (`crates/cli/tests/cli_tests.rs`).
  - Coordinated in-band `Noise_IK` link rekeying (`D-09`, `3600s` / `1 GiB` defaults, monotonic nonces, fail-closed on tamper/EOF/epoch replay).
  - Exit single-resolution SSRF checks (`SEC-204`), bounded DNS timeout (`SEC-201`), non-followed redirects, accept semaphore (`SEC-202`), and keypair validation (`SEC-203`).
- **Properties Tested Only Locally:** Loopback TCP sockets (`127.0.0.1`) via `allow_loopback_for_test = true` + `allowed_targets` in test/demo Exit configs; multi-host WAN latency, Docker/Linux cgroups (`DEFERRED`), and real external TLS targets remain untested.
- **Required Independent Audit Work Before Any Production Use:** External protocol cryptography review (`Noise_IK`/`Noise_NK` `D-08` exporter & `D-09` rekeying), Exit SSRF penetration testing, `cargo-fuzz` harness over wire/cell decoders, and `cargo-audit` CVE scanning.
