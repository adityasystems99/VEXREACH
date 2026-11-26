# Security Design — Private-Relay Protocol (`v0.1`)

> **Status:** Specified (`Phase 1`). Zero cryptographic code is implemented or audited yet.  
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
3. Both peers verify `rs == expected_static_pub`, extract split Noise `TransportState` (`tx`, `rx`), and wrap all cell I/O in `600`-byte padded Noise ciphertext frames (`584B` plaintext + `16B` Noise MAC).
4. **Link Rekey:** Link TCP session closes cleanly and renegotiates fresh ephemeral Noise keys every `3600s` (`1 hour`) or `1 GiB` transferred.

### 2.2 Telescopic Circuit Layer (`Client ↔ Hop i ∈ {1, 2, 3}`)
For each hop `i`:
1. Client constructs `Noise_NK` initiator state with `hop_i.onion_x25519_pub`.
2. Client sends `Noise_NK` `msg1` inside `CREATE` (hop 1) or encrypted `EXTEND` (hops 2–3).
3. Relay `hop_i` completes `Noise_NK` responder handshake, generates `msg2`, and extracts shared secret `ck_i` via `split()` / handshake hash (`get_handshake_hash()` + CSPRNG? — **never mix unauthenticated inputs; use `snow`'s split exporter/HKDF directly from Noise handshake chaining key**).
4. Both Client and `hop_i` derive directional `256`-bit keys via `HKDF-SHA256`:
   - `K_fwd_i = HKDF-Expand(ck_i, b"private-relay-v1/fwd/hop=" || i, 32)`
   - `K_bwd_i = HKDF-Expand(ck_i, b"private-relay-v1/bwd/hop=" || i, 32)`
5. `ck_i` and `HandshakeState` are wrapped in `Zeroizing<[u8; 32]>` and dropped immediately.

---

## 3. Nonce Management, Replay Protection & Integrity

- **Deterministic Counter Nonce (`96` bits):**  
  `nonce(seq) = [0, 0, 0, 0] || seq.to_be_bytes()` (`seq: u64`, initialized at `0` per direction).
- **Associated Authenticated Data (AAD):**  
  Every hop `ChaCha20-Poly1305` operation binds `aad = circuit_id.to_be_bytes() || protocol_version || command || seq.to_be_bytes()` so ciphertext cannot be transplanted across circuits, versions, commands, or sequence indices.
- **Strict FIFO Verification:** Over reliable TCP links, incoming `RELAY_DATA` cell sequence numbers **must satisfy `cell.seq == state.expected_seq`**. Any mismatch (`< expected_seq` replay, `> expected_seq` gap/tamper) triggers immediate circuit teardown (`DESTROY`) without oracle error details.
- **Counter Ceiling:** Hard cap `MAX_SEQ = 2^32` per circuit key; circuit is forced closed cleanly well before wraparound.

---

## 4. Relay Authentication & Trust Boundaries

1. **Relay-to-Relay & Client-to-Entry:** Static `X25519` keys pinned via TOML descriptors (`v0.1`) or signed Coordinator manifests (`Phase 6`). A peer presenting an unexpected `Noise_IK` static key is rejected at handshake completion before allocating any circuit state.
2. **Client Unlinkability:** Client **never** uses a static identity key in `Noise_NK` circuit handshakes, and on `Client → Entry` `Noise_IK` links in `v0.1` the Client uses a fresh **per-session ephemeral static keypair** rather than a persistent machine key—preventing cross-session Client tracking at `Entry`.
3. **Exit SSRF & DNS Isolation Boundary:**
   - Client serializes target hostname as a UTF-8 string inside Exit-encrypted `InnerPayload::Begin`—never resolving DNS on the client.
   - Exit resolves DNS strictly over configured safe resolvers and checks **every** returned `IpAddr` before `TcpStream::connect`:
     - **IPv4 Denied:** `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`.
     - **IPv6 Denied (Default):** `::/128`, `::1/128`, `fe80::/10` (link-local), `fc00::/7` (ULA), `ff00::/8` (multicast), IPv4-mapped `::ffff:0:0/96` wrapping any private IPv4 above. *(Loopback override strictly gated behind test-only feature/config flag `allow_loopback_for_test = false`.)*

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
3. Fixed `600`-byte link frames mitigate single-cell size leakage only; **total burst volume and inter-packet timing remain exposed** to dual-ended network observers until cover traffic / mix scheduling is evaluated in future work.
