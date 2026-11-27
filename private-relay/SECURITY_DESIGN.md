# Security Design — Private-Relay Protocol (`v0.1`)

> **Status:** Implemented Prototype (`Day 5 — v0.1`). Standard cryptographic crates compiled and verified across local bare-metal (`40/40` workspace tests) and hardened 5-container Docker Compose E2E (`12/12` scenarios); independent external cryptographic audit has NOT been performed.  
> **Rule:** Never invent cryptographic algorithms, never log secret key material or PII, and never treat unit tests as equivalent to independent cryptographic review.

---

## 1. Cryptographic Building Blocks (Established Primitives Only)

| Responsibility | Primitive / Construction | Rust Crate (`Phase 3+`) | Why Chosen |
| :--- | :--- | :--- | :--- |
| **Outer Peer Link Handshake & Transport** | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | `snow` | 1-RTT mutually authenticated forward-secret link when responder's static `X25519` key is known; hides initiator identity under encrypted payload (`IK`). |
| **Telescopic End-to-Hop Key Exchange** | `Noise_NK_25519_ChaChaPoly_BLAKE2s` | `snow` | Client knows relay static `X25519` key (`K`) but sends zero client static identity (`N`); stops Entry MITM without linkable client identity. |
| **Per-Hop Onion AEAD** | `ChaCha20-Poly1305` (RFC 8439) | `chacha20poly1305` | Constant-time software performance on CPUs without AES-NI; pure-Rust audited crate with strong tag authentication. |
| **Per-Hop Directional KDF** | `HKDF-SHA256` (RFC 5869) | `hkdf` + `sha2` | Cryptographic domain separation across `fwd`/`bwd` directions and hop index. |
| **Relay Identity Signing (`Phase 6`)** | `Ed25519` (RFC 8032) | `ed25519-dalek` | Fast, deterministic signatures for coordinator relay descriptors and `X25519` onion-key rotation certificates. |
| **Secret Hygiene** | Automatic zero-on-drop | `zeroize` | Scrubs ephemeral scalars, chaining keys, and torn-down circuit AEAD keys from process memory. |

---

## 2. Key Exchange, Key Separation & Zeroization Lifecycle

### 2.1 Link Layer (`Peer ↔ Peer`)
1. Relay `A` connects to Relay `B` over TCP using `B`'s expected static `X25519` key (`static_pub_B`).
2. `Noise_IK`: `A -> B: e, es, s, ss` (`msg1`), `B -> A: e, ee, se` (`msg2`).
3. Both peers verify `rs == expected_static_pub`, extract split Noise `TransportState` (`tx`, `rx`), and wrap all cell I/O in fixed `600`-byte total on-wire Noise frames (`2B` length prefix `== 598` + `582B` padded outer plaintext + `16B` Noise MAC = `600B`).
4. **Link Rekey (`Implemented Day 3 — D-09`):** `LinkSession` enforces configurable time (`3600s` default) and byte (`1 GiB` default) rotation thresholds before sending past threshold. Outgoing sender emits a `600`-byte encrypted `RekeyControl` frame (`0xFFFF || b"PR_REKEY" || version || monotonic_epoch`) at nonce `n` and calls `snow::TransportState::rekey_outgoing()`, advancing keys while keeping nonces strictly monotonic; receiver authenticates `RekeyControl`, verifies `epoch == expected + 1`, and calls `rekey_incoming()`, failing closed (`is_failed() = true` + connection drop) on any AEAD, magic, epoch, or truncated-frame error.

### 2.2 Telescopic Circuit Layer (`Client ↔ Hop i ∈ {1, 2, 3}`)
For each hop `i`:
1. Client constructs `Noise_NK` initiator state with `hop_i.onion_x25519_pub`.
2. Client sends `Noise_NK` `msg1` inside `CREATE` (hop 1) or encrypted `EXTEND` (hops 2–3).
3. Because `snow v0.9.6` encapsulates raw Noise chaining keys unless `risky-raw-split` is enabled, Client and `hop_i` exchange fresh 32-byte CSPRNG seeds encrypted under the Noise handshake payloads (`c_seed` inside `msg1` under `es`; `r_seed` inside `msg2` under `es, ee`) and derive `ck_i` via `HKDF-SHA256::new(Some(transcript_hash), c_seed || r_seed)` bound to `snow::HandshakeState::get_handshake_hash()` (`Decision D-08`), preserving forward secrecy via `ee` while guaranteeing identical exporter keys cleanly.
4. Both Client and `hop_i` derive directional `256`-bit keys via `HKDF-SHA256`:
   - `K_fwd_i = HKDF-Expand(ck_i, b"private-relay-v1/fwd/hop=" || i, 32)`
   - `K_bwd_i = HKDF-Expand(ck_i, b"private-relay-v1/bwd/hop=" || i, 32)`
5. `ck_i` and `HandshakeState` are wrapped in `Zeroizing<[u8; 32]>` and dropped immediately.

---

## 3. Nonce Management, Replay Protection & Integrity

- **Deterministic Counter Nonce (`96` bits):**  
  `nonce(seq) = [0, 0, 0, 0] || seq.to_be_bytes()` (`seq: u64`, initialized at `0` per direction).
- **Associated Authenticated Data (AAD) (`Approved Correction D-07`):**  
  End-to-end per-hop `ChaCha20-Poly1305` AEAD MUST NOT bind a link-local `circuit_id` (`C1`, `C2`, `C3`), because Entry allocates `C2` and Middle allocates `C3` without revealing them to Client. Instead:
  1. **Link Layer (`Noise_IK`):** Authenticates each `600`-byte link frame on adjacent hops, protecting link-local `circuit_id`, `version`, `command`, `payload_len`, and `flags`.
  2. **End-to-End Hop Layer (`ChaCha20-Poly1305`):** Binds `aad = b"PRv1" || version (u8) || direction (u8: 0x01=fwd, 0x02=bwd) || hop_index (u8: 1|2|3) || seq (u64 BE)` (`15` bytes). Cross-circuit isolation is cryptographically guaranteed by deriving fresh ephemeral per-circuit, per-hop `K_fwd_i` / `K_bwd_i` keys from each `Noise_NK` handshake.
- **Strict FIFO Verification:** Over reliable TCP links, incoming `RELAY_DATA` cell sequence numbers **must satisfy `cell.seq == state.expected_seq`**. Any mismatch (`< expected_seq` replay, `> expected_seq` gap/tamper) triggers immediate circuit teardown (`DESTROY`) without oracle error details.
- **Counter Ceiling:** Hard cap `MAX_SEQ = 2^32` per circuit key; circuit is forced closed cleanly well before wraparound.

---

## 4. Relay Authentication & Trust Boundaries

1. **Relay-to-Relay & Client-to-Entry:** Static `X25519` keys pinned via TOML descriptors (`v0.1`) or signed Coordinator manifests (`Phase 6`). A peer presenting an unexpected `Noise_IK` static key is rejected at handshake completion before allocating any circuit state.
2. **Client Unlinkability:** Client **never** uses a static identity key in `Noise_NK` circuit handshakes, and on `Client → Entry` `Noise_IK` links in `v0.1` the Client uses a fresh **per-session ephemeral static keypair** rather than a persistent machine key—preventing cross-session Client tracking at `Entry`.
3. **Exit SSRF & DNS Isolation Boundary:**
   - Client serializes target hostname as a UTF-8 string inside Exit-encrypted `InnerPayload::Begin`—never resolving DNS on the client.
    - Exit resolves DNS strictly over configured safe resolvers inside `timeout(dest_timeout, ...)` (`SEC-201`), checks **every** returned `IpAddr` before `TcpStream::connect(validated_addr)`, and denies private/reserved ranges:
      - **IPv4 Denied:** `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`.
      - **IPv6 Denied (Default):** `::/128`, `::1/128`, `::/96` IPv4-compatible, `::ffff:0:0/96` IPv4-mapped, `::ffff:0:0:0/96` SIIT, `0100::/64`, `64:ff9b::/96` (NAT64), `fe80::/10` (link-local), `fec0::/10` (site-local), `fc00::/7` (ULA), `ff00::/8` (multicast), `2001::/32` (Teredo), `2001:2::/48`, `2001:db8::/32`, `2002::/16` (6to4), plus `%` zone IDs (`D4-01`). *(Test overrides: `allow_loopback_for_test = false`, and `allow_private_targets_for_test = false` strictly gated on non-empty `allowed_targets` for isolated Docker Compose testing — NEVER loosens loopback or `169.254.0.0/16` metadata blocking.)*
4. **Container Isolation Boundaries (`Day 5` Dev Compose vs. Production):**
   - Runtime containers (`debian:bookworm-slim`) drop all Linux capabilities (`cap_drop: [ALL]`), enforce `no-new-privileges:true`, `read_only: true`, non-root `UID/GID 10001`, memory/CPU/PID caps, zero embedded keys inside images, and isolated per-node `:ro` secret volumes generated at startup by `relay-keygen` over an `internal: true` Compose bridge network. Production deployments MUST replace ephemeral init-volume keygen with external KMS/Vault/HSM injection and remove dev target overrides (`allow_private_targets_for_test = false`, `allow_loopback_for_test = false`).

---

## 5. Logging & Telemetry Privacy Contract

| Data Class | Permitted in Logs (`tracing`)? | Permitted in Metrics (`Phase 9`)? |
| :--- | :--- | :--- |
| Raw IP addresses (`Client`, outbound `Destination`) | **NEVER** (redacted in release; omitted in dev by default) | **NEVER** |
| Destination domain names / ports | **NEVER** | **NEVER** |
| Cryptographic keys, nonces, plaintext payloads | **NEVER** | **NEVER** |
| Opaque random `session_tag`, error enum, byte count | Yes (debug/error triage) | Aggregate totals only (no per-circuit labels) |

---

## 6. Unverified Cryptographic & Security Assumptions (Requiring External Audit)

1. `snow`'s `Noise_IK` and `Noise_NK` implementations behave according to Noise Revision 34 under concurrent Tokio cancellation.
2. No timing side-channel exists in Exit SSRF validation (`DNS rebinding` TOCTOU: Exit must connect directly to the **exact validated `SocketAddr`** returned by resolution—never call `connect(hostname)` a second time!).
3. Fixed `600`-byte complete on-wire Noise link frames mitigate single-cell size leakage only; **total burst volume and inter-packet timing remain exposed** to dual-ended network observers until cover traffic / mix scheduling is evaluated in future work.
