# Private-Relay Protocol Specification (`v0.1-draft`)

> **Implementation Status Notice:** This document specifies the target architecture for **Private-Relay v0.1**. Zero components in this specification are implemented in code yet. Every capability described below is categorized explicitly under *Established Technology*, *Proposed Architectural Design*, or *Deferred/Planned*.

---

## A. Overview

### A.1 Protocol Purpose
Private-Relay is a research-oriented, 3-hop overlay communication protocol designed to separate **client network identity** from **destination identity and application payload** by routing traffic through three distinct relay roles (`Entry → Middle → Exit`) wrapped in per-hop authenticated encryption.

### A.2 Problem Statement
In standard direct client-to-server TCP/TLS connections, a single destination server and local ISP see both endpoints of the communication, while a single VPN or TLS proxy sees both the client's source IP address and every destination the client contacts. Existing general-purpose anonymity overlays such as Tor solve large-scale public anonymity via thousands of volunteer nodes, but do not allow operators or engineers to easily run a tightly scoped, auditable, custom-instrumented Rust relay overlay for controlled workloads with explicit cryptographic telemetry.

### A.3 Design Goals
1. **Structural Single-Relay Blindness (3-Hop Split):** Ensure no single honest relay simultaneously observes the client's source IP address, the remote destination address, and the decrypted payload.
2. **Reviewed Cryptography Only:** Construct transport security and telescopic circuit layers exclusively from standardized, audited cryptographic primitives (**Noise Protocol Framework**, `X25519`, `HKDF-SHA256`, `ChaCha20-Poly1305`, `BLAKE2s`).
3. **Bounded Deterministic State:** Enforce hard memory caps on circuit tables, payload frames, and queue depths to prevent amplification and resource exhaustion.
4. **Metadata Minimization:** Prohibit logging of client IP addresses, destination hostnames, circuit keys, or plaintext traffic by default.
5. **Independent Testability:** Enable deterministic local verification on loopback ports (`127.0.0.1`) prior to multi-host deployment.

### A.4 Non-Goals (Explicit Exclusions)
- **Not a Tor Replacement or Global Anonymity Network:** With a small relay set, Private-Relay **does not** defend against global passive observers or dual-ended timing correlation.
- **No Custom Cryptographic Primitives:** Zero bespoke ciphers, hash functions, or non-standard AEAD modes.
- **No Interactive TCP Stream Multiplexing in v0.1 (`Decision D-01`):** v0.1 forwards bounded request/response payloads (`<= 64 KiB`) rather than arbitrary long-lived TCP streams (`SSH`, video streaming). Cells carry a `stream_id` field so stream support remains structurally extensible in future revisions.
- **No Cover Traffic / Mix Batching in v0.1:** Fixed-size outer link frames normalize individual packet sizes, but intentional mix delays and dummy cover cells are deferred (`Planned`).

### A.5 Intended Use Cases
- Privacy-conscious bounded API/HTTP request forwarding where an organizational or federated operator pool wants verifiable structural separation between ingress and egress.
- Educational and security-research testbed for measuring multi-hop circuit latency, AEAD key separation, replay defenses, and traffic correlation limits.

---

## B. System Architecture & Responsibilities

```text
Client  ──(Noise_IK + Layered AEAD)──▶  Entry Relay  ──▶  Middle Relay  ──▶  Exit Relay  ──▶  Destination
```

| Role | What It Knows | What It Must NEVER Know | Core Responsibilities |
| :--- | :--- | :--- | :--- |
| **Client** | Own IP, full 3-hop route (`Entry`, `Middle`, `Exit`), destination target, plaintext payload, all 3 circuit keypairs. | Other clients' circuits. | Select path; run telescopic Noise handshakes; pad/fragment payloads into cells; apply 3 forward AEAD layers; peel 3 backward AEAD layers. |
| **Entry Relay (Hop 1)** | Client source IP, `Middle` relay address, link-local `CircuitId_1 ↔ CircuitId_2`, forward `K_fwd_1` / `K_bwd_1`. | Final `Exit` relay (except when next hop happens to extend to Exit via Middle—Entry only sees `Middle`), Destination address, plaintext payload. | Authenticate client link (`Noise_IK` or anonymous Noise link); enforce per-IP connection/circuit rate limits; strip outer `K_fwd_1` layer; wrap replies with `K_bwd_1`. |
| **Middle Relay (Hop 2)** | `Entry` peer address, `Exit` peer address, `CircuitId_2 ↔ CircuitId_3`, `K_fwd_2` / `K_bwd_2`. | Client source IP, Destination address, plaintext payload. | Relay cells strictly between Entry link and Exit link; peel `K_fwd_2` forward / apply `K_bwd_2` backward; enforce idle & queue bounds. |
| **Exit Relay (Hop 3)** | `Middle` peer address, `CircuitId_3`, `K_fwd_3` / `K_bwd_3`, Destination host/port, plaintext payload (unless Destination uses end-to-end TLS). | Client source IP, `Entry` relay identity. | Peel `K_fwd_3` (final layer); validate destination against SSRF blocklist; resolve DNS locally at Exit; communicate with Destination; wrap responses with `K_bwd_3`. |
| **Destination** | `Exit` relay source IP, incoming request payload. | Client source IP, `Entry` or `Middle` identities. | Process request and return response over outbound Exit connection (ideally over end-to-end HTTPS/TLS from Client → Destination inside the tunnel). |
| **Coordinator (`Phase 5`)** | Signed relay descriptors (`relay_id`, `role`, `addr`, `x25519_pub`, health status). | Active client circuits, user identities, request destinations. | Serve signed relay directory; run passive/active health probes (`Deferred to Phase 5`; static TOML in `v0.1`). |

---

## C. Communication Model

### C.1 Transport & Link Establishment (`Peer ↔ Peer`)
1. Every adjacent peer pair (`Client↔Entry`, `Entry↔Middle`, `Middle↔Exit`) communicates over a persistent **TCP connection**.
2. Immediately upon TCP connect, peers perform an authenticated **Noise Protocol** handshake:
   - `Relay ↔ Relay` and `Client → Relay` (when relay static public key is known from descriptor): **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** (1-RTT, forward secret, authenticates responder's static key and verifies peer link channel).
3. Over an established Noise transport session, all frames are transmitted as **fixed-length `600`-byte outer Noise-encrypted link frames**:
   ```text
   Outer Link Frame Plaintext (584 bytes before 16B Noise link tag -> 600B ciphertext + 2B length prefix)
   +---------------+---------------------+-------------------------------+
   | real_len (u16)| inner_cell (<=582B) | random_padding (to 584 bytes) |
   +---------------+---------------------+-------------------------------+
   ```
   *Purpose:* Passive observers on the TCP wire see uniform `602`-byte TCP records for control cells, `EXTEND` handshakes, and data cells alike.

### C.2 Wire Cell Format (Inside Outer Link Frame)
All overlay cells carry a common `9`-byte header followed by a command-specific body:

```text
+--------------------+---------------+-------------------+-----------------------------+
| circuit_id (u32)   | version (u8)  | command (u8)      | payload_len (u16)           |
+--------------------+---------------+-------------------+-----------------------------+
| flags (u8)         | body (variable up to 573 bytes; total frame padded to 584B)     |
+--------------------+-----------------------------------------------------------------+
```

* **`circuit_id` (`u32`):** Link-local circuit identifier. Chosen independently per link (`C1` on `Client↔Entry`, `C2` on `Entry↔Middle`, `C3` on `Middle↔Exit`). Must be non-zero; MSB indicates link initiator (`0` or `1`) to prevent ID collisions when two relays connect concurrently.
* **`version` (`u8`):** Protocol version (`0x01`). Unknown versions cause immediate cell rejection and circuit teardown.
* **`command` (`u8`):**
  - `0x01` `CREATE` — Client initiates inner `Noise_NK` handshake step 1 with Entry (`msg1`).
  - `0x02` `CREATED` — Entry replies with inner `Noise_NK` step 2 (`msg2`).
  - `0x03` `EXTEND` — Client tunnels next-hop address + `CREATE` (`msg1`) to current end of circuit.
  - `0x04` `EXTENDED` — Intermediate hop returns `CREATED` (`msg2`) back to Client.
  - `0x05` `RELAY_DATA` — Onion-wrapped request/response chunk (`seq: u64`, nested AEAD ciphertexts).
  - `0x06` `DESTROY` — Teardown notification with 1-byte `reason_code`; clears keys immediately.

### C.3 Telescopic Circuit Construction
1. **Hop 1 (`Client ↔ Entry`):** Client picks unused `C1`, sends `CREATE(C1, Noise_NK_msg1_to_Entry)`. Entry processes `Noise_NK`, stores `(C1, K_fwd_1, K_bwd_1)`, replies `CREATED(C1, Noise_NK_msg2)`.
2. **Hop 2 (`Client ↔ Entry ↔ Middle`):** Client encrypts `EXTEND(middle_relay_id, Noise_NK_msg1_to_Middle)` under `K_fwd_1` inside a `RELAY_DATA` / `EXTEND` envelope. Entry peels `K_fwd_1`, looks up `middle_addr` (ensuring existing or new `Noise_IK` link to Middle), picks unused `C2`, sends `CREATE(C2, Noise_NK_msg1_to_Middle)`. Middle stores `(C2, K_fwd_2, K_bwd_2)` and returns `CREATED(C2, Noise_NK_msg2)`. Entry wraps `msg2` with `K_bwd_1` and returns `EXTENDED(C1, ...)` to Client.
3. **Hop 3 (`Client ↔ Entry ↔ Middle ↔ Exit`):** Client wraps `EXTEND(exit_relay_id, Noise_NK_msg1_to_Exit)` under `K_fwd_2` then `K_fwd_1`. Entry peels `K_fwd_1`, Middle peels `K_fwd_2`, Middle creates `C3` with Exit via `CREATE(C3, msg1)`, and `EXTENDED` propagates backward (`K_bwd_2`, `K_bwd_1`) to Client.

### C.4 Request & Response Forwarding (`Decision D-01`: Bounded Request/Response)
Inside the innermost decrypted payload at `Exit` (and Client on response):

```text
Inner Payload (max 492 bytes per cell)
+----------------+----------------+------------------+----------------------------+
| request_id u32 | chunk_seq u16  | inner_flags u8   | fragment (<= 485 bytes)    |
+----------------+----------------+------------------+----------------------------+
  inner_flags: bit 0 = FIRST (includes target_addr_len + target_addr + port on req)
               bit 1 = FINAL (end of request / response message)
               bit 2 = ERROR (Exit returns sanitized error code if Destination fails)
```

1. **Request Forwarding:** Client fragments a bounded request (`<= 64 KiB`, `<= 140` cells) into `Inner Payload` chunks. For each cell, Client applies 3 AEAD layers (`Exit` `K_fwd_3`, then `Middle` `K_fwd_2`, then `Entry` `K_fwd_1`). Each relay verifies & strips its outer layer and forwards along its `(in_conn, in_cid) -> (out_conn, out_cid)` mapping. Exit reassembles up to `64 KiB`, enforces SSRF rules on `(target_host, target_port)`, connects to Destination, and transmits the request.
2. **Response Forwarding:** Exit reads Destination's bounded response (`<= 64 KiB`, subject to read timeout), splits it into `Inner Payload` chunks with matching `request_id`, encrypts with `K_bwd_3`, and sends on `C3` toward Middle. Middle encrypts with `K_bwd_2` onto `C2`; Entry encrypts with `K_bwd_1` onto `C1`. Client peels `K_bwd_1`, `K_bwd_2`, `K_bwd_3` in order and reassembles the response.

### C.5 Session Lifecycle & Termination
- **Circuit Idle TTL:** Default `120s` since last valid cell; expired circuits send `DESTROY(IDLE_TIMEOUT)` in both directions and zeroize all key material.
- **Max Circuit Lifetime:** Hard cap of `1800s` (30 minutes) forcing fresh circuit rotation (`Phase 5`).
- **Error Teardown:** Any AEAD verification failure, invalid sequence number, unknown `circuit_id`, or broken upstream link triggers immediate `DESTROY` downstream/upstream and key zeroization.

---

## D. Cryptographic Architecture

### D.1 Evaluation of Established Constructions
| Layer | Evaluated Alternatives | Chosen Construction | Justification |
| :--- | :--- | :--- | :--- |
| **Outer Link Security** | Raw TLS 1.3 (`rustls`) vs. Noise (`snow`) | **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** (`snow`) | Lightweight, deterministic state machine without X.509 PKI certificate management overhead in v0.1; provides 1-RTT mutual auth and forward secrecy against relay static `X25519` keys. |
| **Telescopic Hop Handshake** | Custom signed X25519 vs. `Noise_NK` | **`Noise_NK_25519_ChaChaPoly_BLAKE2s`** (`snow`) | Client already knows target relay static public key (`K`) but stays unauthenticated (`N`); prevents active MITM by Entry/Middle relays in 1 round trip without inventing a custom handshake transcript. |
| **Per-Hop Onion Cipher** | `AES-256-CTR` + digest vs. `ChaCha20-Poly1305` AEAD | **`ChaCha20-Poly1305` (`chacha20poly1305` crate)** | Eliminates padding/timing oracle and unauthenticated malleability (tagging attacks stopped immediately at the first relay whose tag fails). |
| **Key Derivation** | Direct use of Noise split keys vs. explicit HKDF | **Noise `HandshakeState::split()` + `HKDF-SHA256` (`hkdf` crate)** | Clean cryptographic domain separation between `fwd`, `bwd`, and future rotation subkeys. |

### D.2 Key Derivation & Separation
Upon completing `Noise_NK` for hop `i ∈ {1, 2, 3}`:
1. Extract 32-byte shared chaining key `ck_i` / split secret from Noise handshake state.
2. Derive independent 256-bit directional keys via `HKDF-SHA256`:
   - `K_fwd_i = HKDF-Expand(ck_i, info = "private-relay-v1|fwd|hop=" || i, len = 32)`
   - `K_bwd_i = HKDF-Expand(ck_i, info = "private-relay-v1|bwd|hop=" || i, len = 32)`
3. Zeroize `ck_i` and all ephemeral `X25519` scalars immediately (`zeroize` crate).

### D.3 Nonce Handling & Replay Protection
- AEAD nonce (`96` bits / `12` bytes) is **never randomly chosen** for data cells; it is constructed deterministically as:
  `nonce = [0x00, 0x00, 0x00, 0x00] || seq.to_be_bytes()` (8-byte big-endian unsigned integer `seq`).
- Every hop maintains two strictly monotonic counters (`expected_fwd_seq: u64`, `next_bwd_seq: u64` — and similarly at Client).
- **Strict Replay Rule (over reliable TCP):** Since TCP delivers cells in strict FIFO order per connection/circuit, each incoming `RELAY_DATA` cell's `seq` **MUST equal `expected_seq`**. Any cell with `seq != expected_seq` (duplicate, replayed, or reordered by tampering) triggers immediate `AEAD/Sequence Error` and `DESTROY`.
- **Sequence Exhaustion:** At `seq >= 2^32` on a single circuit (`~2 TiB` max per key), the relay refuses further cells and tears down the circuit before counter wraparound is even remotely possible.

### D.4 Key Rotation
- Ephemeral circuit keys rotate automatically via **circuit replacement** (`Max Lifetime = 1800s` or `Max Bytes = 256 MiB` per circuit in `Phase 5`).
- Outer `Noise_IK` link TCP sessions reconnect/rekey every `3600s` (`1 hour`).
- Relay static `X25519` keys support scheduled rotation via versioned signed descriptors (`Phase 5`).

### D.5 Relay Authentication
- Each relay holds a persistent `Ed25519` signing identity keypair (`identity.key`) and a periodic `X25519` onion-routing static keypair (`onion.key`) signed by its `Ed25519` identity (`Phase 5` coordinator verification; in `v0.1` local TOML config binds trusted relay public keys explicitly).
- Client **never** authenticates with a persistent identity key during `Noise_NK`, preserving unlinkability across circuits.

---

## E. Routing Architecture

| Stage | `v0.1` (Phases 2–4 Local Prototype) | `v0.2+` (Phase 5 Coordinator & Dynamic Routing) |
| :--- | :--- | :--- |
| **Relay Discovery** | Static `relays.toml` file specifying `relay_id`, `role`, `addr`, `x25519_pub`. | Authenticated HTTP/TLS Coordinator (`Axum` + `PostgreSQL`) serving signed directory documents (`Ed25519`). |
| **Relay Selection** | Deterministic selection of 1 local `Entry`, 1 `Middle`, 1 `Exit`. | Weighted random selection enforcing **distinct operator/subnet/AS separation** (never pick two relays from the same operator or `/24`/`/48` subnet in one circuit). |
| **Route Construction** | Synchronous telescopic `CREATE` → `EXTEND` → `EXTEND` with per-hop 5s timeout. | Concurrent circuit pre-building pool with path validation probes. |
| **Route Failure & Recovery** | Any timeout/EOF/bad-tag tears down the circuit via `DESTROY` and surfaces clean error to client. | Automatic circuit eviction on health failure + transparent retry on a freshly selected non-overlapping path (up to bounded retry limit = `2`). |

---

## F. Operational Architecture

- **Configuration:** Strictly typed `TOML` config validated via `serde` at startup (`relay.toml`, `client.toml`). Relays fail closed if keys are missing or file permissions are insecure.
- **Logging:** `tracing` structured logs. **Invariant:** Never log IP addresses at Info/Warn/Error level in production profile, never log destination domains/IPs, never log raw buffers or keys. Only log opaque local `conn_token`, cell counts, and error enums.
- **Monitoring (`Phase 6`):** Aggregate Prometheus counters (`active_circuits`, `cells_forwarded_total`, `handshake_failures_total`, `circuit_build_duration_ms`). No per-user histograms.
- **Error Handling:** Typed Rust error enums (`ProtocolError`, `CryptoError`, `RelayError`, `ExitPolicyError`). Cryptographic failures never leak whether the tag, sequence number, or inner field failed across the wire (`DESTROY(CRYPTO_FAIL)` only).
- **Resource Limits (Relay Defaults):**
  - `max_concurrent_circuits`: `1024`
  - `max_circuits_per_peer_ip` (`Entry` only): `16`
  - `circuit_channel_capacity`: `64` cells (`~38 KiB` buffered per circuit)
  - `max_request_bytes` / `max_response_bytes`: `65,536` bytes (`64 KiB`)
  - `handshake_timeout_ms`: `5000`, `idle_circuit_ttl_s`: `120`

---

## G. Protocol Limitations (Explicit Engineering Honesty)

1. **Traffic Correlation & Timing Attacks:** An adversary observing both `Client ↔ Entry` and `Exit ↔ Destination` can match packet bursts and round-trip latencies despite 3-layer encryption. **Status:** *Unmitigated in v0.1.*
2. **Packet Size & Cell Counting:** Outer fixed `600`-byte link frames hide individual cell types, **not** total request/response byte volume (`4` cells vs `80` cells reveals payload scale). **Status:** *Unmitigated without cover padding.*
3. **Hop-Position Length Visibility Inside `Noise_IK`:** Because nested `ChaCha20-Poly1305` removes `16` bytes per hop inside the `584`-byte link envelope, `Entry` sees `544B` (`+24B` seq+tag × 3), `Middle` sees `520B`, and `Exit` sees `496B`. In our fixed 3-role topology (`Entry / Middle / Exit`) relays already know their role, **but** arbitrary `N`-hop anonymity requires constant-size Sphinx headers (`Future work`).
4. **Malicious / Colluding Relays (`Entry + Exit`):** If the same attacker controls both Entry and Exit, Entry knows client IP and Exit knows destination—timing correlation links the user cleanly.
5. **Centralized Coordinator Risk (`Phase 5`):** A single directory service can perform **route-partitioning attacks** (serving different relay subsets to targeted users) unless descriptors carry multi-party consensus signatures or client-pinned directory hashes.
6. **DNS & Network Metadata Leaks:** Client DNS is protected **only** if Destination resolution runs exclusively at Exit. Local OS telemetry, client clock skew, or non-tunneled background traffic on the client device still leak metadata outside Private-Relay.
