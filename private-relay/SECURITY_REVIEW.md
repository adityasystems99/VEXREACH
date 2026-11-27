# Internal Security Review Report — Private-Relay (`v0.1`)

> **Date:** `2026-11-27`  
> **Scope:** Focused engineering code review across `crates/protocol`, `crates/crypto`, `crates/network`, `crates/relay`, `crates/client`, and `crates/cli` (`v0.1` local prototype).  
> **Important Notice:** This is an internal engineering security review. **Private-Relay v0.1 is NOT production-ready, NOT production-secure, and does NOT claim global anonymity or resistance to passive timing/volume traffic analysis.** Independent external cryptographic and systems audits have NOT been performed.

---

## 1. Component Inspection Findings (16-Point Audit)

| # | Area | Implementation File(s) Reviewed | Findings & Verification Status |
| :--- | :--- | :--- | :--- |
| 1 | **`Noise_IK` Link Authentication** | [crates/crypto/src/link.rs](./crates/crypto/src/link.rs), [crates/crypto/src/keys.rs](./crates/crypto/src/keys.rs), [crates/network/src/transport.rs](./crates/network/src/transport.rs) | Verified: Binds prologue `b"private-relay-link-v1"`, requires `remote_static_pub == expected_remote_pub`, rejects wrong server keys during `Noise_IK` handshake (`tcp_link_rejects_bad_prefix_truncated_eof_and_bad_auth`, `e2e_relay_unavailable_and_wrong_pubkey_fail_cleanly`). Hardened `StaticKeypair::from_slices` to mathematically validate `public == X25519(private)` and reject all-zero keys. |
| 2 | **`Noise_NK` Telescopic Hops** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs) | Verified: Initiator uses `N` (no static identity key), Responder pins `K` (relay X25519 key), binds `b"private-relay-hop-v1"`, prevents Entry MITM against Middle (`hop_nk_handshake_rejects_spoofed_identity_and_bad_messages`). |
| 3 | **`HKDF-SHA256` Key Derivation** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs) | Verified (`D-08`): Combines Noise transcript hash (`get_handshake_hash()`) as HKDF salt with `c_seed \|\| r_seed` encrypted under `es` / `es, ee`, deriving strictly separated directional keys via `b"private-relay-v1/fwd/hop="` and `b"private-relay-v1/bwd/hop="` (wrapping `Zeroizing<[u8; 32]>`). |
| 4 | **`ChaCha20-Poly1305` Nonce Handling** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs), `snow` `TransportState` | Verified: Per-hop AEAD builds 96-bit nonce `[0,0,0,0] \|\| seq_be` with strict cap `MAX_CIRCUIT_SEQ = 2^32`. Outer `Noise_IK` link rekeying uses `snow::TransportState::rekey_outgoing`/`rekey_incoming` (`REKEY(k)`), preserving monotonic nonces (`self.n` increments, never resets to `0`). |
| 5 | **15-Byte AEAD AAD (`D-07`)** | [crates/protocol/src/cell.rs](./crates/protocol/src/cell.rs) | Verified: Binds `b"PRv1" \|\| version \|\| direction \|\| hop_index \|\| seq` (`15B`), omitting link-local `CircuitId` while binding direction and hop index (`aead_tamper_wrong_key_aad_metadata_replay_and_exhaustion`). |
| 6 | **FIFO Sequencing & Replay Protection** | [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs), [crates/crypto/src/link.rs](./crates/crypto/src/link.rs) | Verified: Incoming `RELAY_DATA` enforces `seq == expected_seq`; gaps/replays fail decryption/validation and trigger `DestroyReason::CryptoFail`. Link rekey control frames enforce strictly monotonic `epoch == incoming_rekey_epoch + 1` and mark `LinkSession::failed = true` (fail-closed) on any AEAD/framing/epoch error. |
| 7 | **Fixed `600`-Byte Link Framing (`D-02`)** | [crates/protocol/src/frame.rs](./crates/protocol/src/frame.rs) | Verified: Compile-time assertions lock `2B outer_len (598) + 582B plaintext + 16B MAC = 600B`; filler comes from `OsRng`; link rekey control frames (`0xFFFF \|\| b"PR_REKEY"`) share identical `600`-byte wire sizing. *Trade-off (`KI-03`):* per-hop lengths remain distinguishable inside `582B` plaintext at honest relays. |
| 8 | **`CircuitId` Handling** | [crates/protocol/src/circuit.rs](./crates/protocol/src/circuit.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | Verified: Rejects `CircuitId(0)`; MSB ownership (`0x8000_0000`) prevents link-initiator collisions; identifiers are strictly link-local (`C1`, `C2`, `C3`), never revealed end-to-end. |
| 9 | **Request Chunking & Reassembly** | [crates/protocol/src/message.rs](./crates/protocol/src/message.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | Verified (`D-01`): Hard bounds (`<= 65_536B` body, `<= 255B` target addr, `<= 140` chunks, single-flight active request per circuit, `used_request_ids` replay filter at Exit). |
| 10 | **Exit SSRF Protections** | [crates/network/src/policy.rs](./crates/network/src/policy.rs) | Verified: `allow_loopback_for_test` defaults to `false`; explicitly blocks IPv4 `0.0.0.0/8`, RFC1918, loopback, link-local `169.254.0.0/16`, CGNAT `100.64.0.0/10`, benchmarking `198.18.0.0/15`, multicast/broadcast/`>=240.0.0.0`, and IPv6 `::/128`, `::1`, `fe80::/10`, `fc00::/7`, `ff00::/8`, `64:ff9b::/96` (NAT64), `2001:db8::/32`, and IPv4-mapped `::ffff:0:0/96`. Rejects whitespace and control chars in targets. |
| 11 | **DNS Resolution & TOCTOU Check** | [crates/network/src/policy.rs](./crates/network/src/policy.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | **Confirmed Safe Against Application-Level TOCTOU Rebinding:** Client never resolves DNS (`--url` serializes hostname verbatim). Exit calls `lookup_host(target).await` **once**, validates **every** returned `SocketAddr`, returns validated `resolved[0]: SocketAddr`, and `execute_destination_request` passes that `SocketAddr` directly to `TcpStream::connect(validated_addr)` without ever re-resolving the hostname. *(Note: assumes OS resolver does not forge internal DNS responses on a compromised Exit host.)* |
| 12 | **HTTP Redirect Behavior** | [crates/cli/src/lib.rs](./crates/cli/src/lib.rs), [crates/relay/src/engine.rs](./crates/relay/src/engine.rs) | **Confirmed Safe:** Neither `Exit` nor `relay-client` parses or follows HTTP `3xx Location` redirects; `302 Location: http://169.254.169.254/...` returns once as passive bytes (`e2e_redirect_response_is_not_followed_to_ssrf_target` + `/redirect-ssrf` demo case). |
| 13 | **IPv4 & IPv6 Policy Parity** | [crates/network/src/policy.rs](./crates/network/src/policy.rs), [crates/network/tests/network_tests.rs](./crates/network/tests/network_tests.rs) | Verified: `::ffff:127.0.0.1` and `::ffff:10.0.0.1` route cleanly through `validate_ipv4`; ULA, link-local, loopback, NAT64 tested. |
| 14 | **Resource Exhaustion Defenses** | [crates/relay/src/engine.rs](./crates/relay/src/engine.rs), [crates/network/src/transport.rs](./crates/network/src/transport.rs) | Verified: Semaphore `max_concurrent_connections` (default `256`) drops excess TCP accepts before handshake; `max_concurrent_circuits` (`1024`), Entry `max_circuits_per_peer_ip` (`16`), `mpsc(64)` bounded queues, `MAX_CONSECUTIVE_REKEYS = 4`, handshake/I/O timeouts, `120s` idle circuit TTL, and `64 KiB` destination read abort. |
| 15 | **Logging & Secret Redaction** | [crates/relay/src/engine.rs](./crates/relay/src/engine.rs), [crates/cli/src/lib.rs](./crates/cli/src/lib.rs) | Verified: Custom `Debug` impls redact secret keys; `tracing` fields log only `relay_id`, `role`, `circuit_id`, and enum reasons (`tracing_logs_never_contain_ips_destinations_keys_or_payloads`); `relay-client` suppresses raw bodies unless `--print-body` is explicitly supplied. |
| 16 | **Key Lifecycle & Cleanup** | [crates/crypto/src/keys.rs](./crates/crypto/src/keys.rs), [crates/crypto/src/hop.rs](./crates/crypto/src/hop.rs), [crates/crypto/src/link.rs](./crates/crypto/src/link.rs) | Verified: `StaticKeypair`, `HopCipherState`, `HopCipherPair`, and `ClientCircuitCrypto` implement `ZeroizeOnDrop`; temporary key/seed buffers use `Zeroizing` / `.zeroize()`; torn circuits drop key state and `CircuitSlotGuard` decrements capacities. *(Note: `snow::TransportState` owns symmetric `CipherState`s cleanly inside `LinkSession`, though `snow` internals do not expose a user-callable explicit zeroize trait beyond drop.)* |

---

## 2. Classification of Assurance & Honest Limitations

### Verified Implementation Properties
- End-to-end 3-hop `Client → Entry → Middle → Exit → Destination` forwarding across separate Windows OS processes (`crates/cli/tests/cli_tests.rs` and `demo/run-demo.ps1`).
- Coordinated Noise Section 4.2/11.3 in-band link rekeying (`LinkRekeyPolicy`, `3600s` / `1 GiB` defaults, fail-closed epoch/AEAD checks).
- Zero application-level DNS TOCTOU rebinding (`TcpStream::connect(validated_addr)`) and non-following redirect handling.
- Strict capacity bounds (`max_concurrent_connections`, `max_concurrent_circuits`, `max_circuits_per_peer_ip`, bounded `mpsc(64)` backpressure, `64 KiB` caps).

### Properties Tested Only in a Local Environment
- All tests ran on Windows `localhost` (`127.0.0.1`) loopback sockets using local `demo-dest` and `relay-keygen` ephemeral identities (`allow_loopback_for_test = true` strictly inside test/demo Exit configs). Multi-host WAN NAT/firewall traversal, TLS-over-tunnel destination certificates, and sustained multi-hour internet link rekeying have NOT been tested.

### Unverified Security Assumptions
1. Correctness of `snow v0.9.6`, `chacha20poly1305 v0.10.1`, `hkdf v0.12.4`, and underlying `tokio` runtime under adversarial concurrent cancellation.
2. Integrity of the Exit host's configured OS DNS resolver (a compromised local DNS server on Exit could resolve an allowed public domain if `allowed_targets` is left empty, though SSRF IP blocks still apply to returned IPs).
3. Absence of OS-level core dumps/swap leaks on Windows (`ZeroizeOnDrop` scrubs Rust heap memory on drop, not prior OS swap pages).

### Known Attacks Outside Current Protection (`v0.1`)
- **Dual-ended passive traffic correlation & burst volume analysis (`KI-01`):** Watching both `Client ↔ Entry` and `Exit ↔ Destination` correlates packet counts and timing despite 3-hop encryption and `600`-byte outer cells.
- **Colluding `Entry + Exit` relays (`KI-02`):** No federated directory or `/24`/`/48` operator diversity enforcement exists until Phase 5/6 Coordinator.
- **Endpoint compromise:** Malware on Client or root compromise on Exit defeats secrecy/anonymity within that compromised zone.
- **Volumetric L3/L4 SYN/bandwidth floods:** Application-layer `max_concurrent_connections` drops excess `accept()` sockets after kernel TCP handshake; kernel/firewall rate limits are still needed on public hosts.

### Required Independent Audit Work Before Any Production Use
1. Formal cryptographic protocol review of `Noise_IK` + `Noise_NK` seed exporter (`D-08`), `LinkSession` in-band rekey framing, and `ChaCha20-Poly1305` nonce/epoch invariants.
2. Independent penetration test of Exit SSRF rules (IPv4/IPv6 transition mechanisms, resolver edge cases), parser fuzzing (`cargo-fuzz` on `protocol::Cell::decode` / `InnerPayload::decode` / `OuterFramePlaintext`), and resource-exhaustion stress testing under Linux production profiles.
