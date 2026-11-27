# Architecture — Private-Relay Protocol (`v0.1`)

---

## 1. High-Level System Architecture

```mermaid
flowchart LR
    subgraph ClientHost["Client Trust Zone"]
        App["Client App / CLI"]
        CProto["Circuit Manager & 3-Layer Onion Crypto"]
        App --> CProto
    end

    subgraph Network["Untrusted Network / Relays"]
        Entry["Entry Relay (Hop 1) — Sees Client IP, Middle Addr"]
        Middle["Middle Relay (Hop 2) — Sees Entry Addr, Exit Addr"]
        Exit["Exit Relay (Hop 3) — Sees Middle Addr, Destination"]
    end

    subgraph Control["Control Plane (v0.1: Static TOML / Phase 5: Coordinator)"]
        Dir["Directory / Relay Descriptors (Ed25519 Signed Keys)"]
    end

    Dest["Destination Server (Sees Exit IP)"]

    Dir -. "Static TOML / Signed JSON" .-> CProto
    CProto <== "TCP + Noise_IK (600B Link Frames)" ==> Entry
    Entry <== "TCP + Noise_IK (600B Link Frames)" ==> Middle
    Middle <== "TCP + Noise_IK (600B Link Frames)" ==> Exit
    Exit <== "Outbound TCP (+ optional E2E TLS)" ==> Dest
```

---

## 2. Component Responsibilities & Trust Boundaries

1. **Client (`crates/client/`):**
   - Loads verified relay descriptors (`v0.1`: `ClientConfigFile` TOML via `relay-keygen` / `client.toml`; `Phase 5`: signed Coordinator snapshot).
   - Initiates telescopic 3-hop circuit (`CREATE` → `EXTEND` → `EXTEND`) using ephemeral per-session `Noise_IK` keypairs.
   - Wraps bounded requests (`<= 64 KiB`) into fixed inner fragments, encrypts 3 times (`Exit → Middle → Entry`), sends over Entry's `Noise_IK` link, and peels 3 response layers.
2. **Protocol Framing (`crates/protocol/`):**
   - Pure, zero-I/O binary serialization/deserialization for `OuterFramePlaintext` (`600` bytes), `LinkFrame::RekeyControl` (`D-09`), `Cell` (`9B` header), `ExtendDirective`, `RelayHopPlaintext`, and `InnerPayload`.
   - Enforces strict bounds and length invariants prior to crypto or allocation.
3. **Cryptographic Engine (`crates/crypto/`):**
   - Wraps `snow v0.9.6` (`Noise_IK` outer links + synchronized Section 4.2/11.3 link rekeying `D-09`, `Noise_NK` inner telescopic hops + `D-08` transcript-salted HKDF exporter), `hkdf`, `chacha20poly1305`, and `zeroize`.
   - Owns directional cipher states (`HopCipherPair`) with strict monotonic `u64` nonce sequence checks and X25519 keypair consistency validation.
4. **Network & Policy Layer (`crates/network/`):**
   - Owns typed TOML configuration validation (`RelayConfig`, `ClientConfigFile`), `DestinationPolicy` (DNS-once SSRF blocking), and async `LinkReader`/`LinkWriter` transport halves.
5. **Relay Core (`crates/relay/`):**
   - Operates uniformly across `Entry`, `Middle`, and `Exit` roles via configuration (`role = "entry" | "middle" | "exit"`).
   - Enforces accept-time `max_concurrent_connections` semaphore, `max_concurrent_circuits`, Entry `max_circuits_per_peer_ip`, bounded `mpsc` channels, cancellation-safe hop extension, and direct validated `SocketAddr` connect at Exit.
6. **CLI Binaries (`crates/cli/`) & Local Demo (`demo/`):**
   - Standalone executables (`relay-entry`, `relay-middle`, `relay-exit`, `relay-client`, `demo-dest`, `relay-keygen`) running as separate OS processes over localhost TCP sockets.
7. **Coordinator (`coordinator/` — Deferred to Phase 5):**
   - Optional HTTP/Axum registry + PostgreSQL store for relay health and signed descriptor publishing. Not created until Phase 5.

### Cryptographic & Trust Boundaries
- **Boundary 1 (Client OS):** Plaintext & destination exist in Client RAM. Protected only by Client host security.
- **Boundary 2 (Wire Links):** Protected by `Noise_IK` over TCP (`600B` fixed frames). Passive eavesdroppers cannot read cell commands or ciphertexts.
- **Boundary 3 (Entry ↔ Middle):** `Entry` strips layer 1 (`K_fwd_1`), revealing **only** `NextHop = Middle` and an encrypted blob for `Middle`.
- **Boundary 4 (Middle ↔ Exit):** `Middle` strips layer 2 (`K_fwd_2`), revealing **only** `NextHop = Exit` and an encrypted blob for `Exit`.
- **Boundary 5 (Exit ↔ Destination):** `Exit` strips layer 3 (`K_fwd_3`) and resolves `target_host:port`. Unless Client encrypts end-to-end via TLS inside the request, `Exit` sees application plaintext.

### 2.1 Trust Boundaries Diagram

```mermaid
flowchart TB
    subgraph TB1["Zone 1: Client Device (Trusted by User)"]
        Plain["Plaintext Request & Target Hostname"]
        Keys["Ephemeral Circuit Keys K1, K2, K3"]
    end

    subgraph TB2["Zone 2: Entry Relay (Untrusted for Destination)"]
        EData["Knows: Client IP + Middle Addr / Blind to: Target + Plaintext"]
    end

    subgraph TB3["Zone 3: Middle Relay (Blind Transit)"]
        MData["Knows: Entry Addr + Exit Addr / Blind to: Client IP + Target + Plaintext"]
    end

    subgraph TB4["Zone 4: Exit Relay (Untrusted for Client IP)"]
        XData["Knows: Target Host + Plaintext if non-TLS / Blind to: Client IP"]
    end

    subgraph TB5["Zone 5: Destination Server"]
        DData["Knows: Exit IP + Request / Blind to: Client IP"]
    end

    TB1 -- "Noise_IK + 3 Onion Layers" --> TB2
    TB2 -- "Noise_IK + 2 Onion Layers" --> TB3
    TB3 -- "Noise_IK + 1 Onion Layer" --> TB4
    TB4 -- "Outbound TCP / Optional E2E TLS" --> TB5
```

---

## 3. Data Flow & Sequence Diagrams

### 3.1 Telescopic Circuit Establishment (`CREATE` → `EXTEND` → `EXTEND`)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant E as Entry Relay
    participant M as Middle Relay
    participant X as Exit Relay

    C->>E: TCP + Noise_IK Handshake (Link 1)
    C->>E: CREATE(cid=C1, Noise_NK_msg1_Entry)
    E-->>C: CREATED(cid=C1, Noise_NK_msg2_Entry)
    Note over C,E: Shared Hop 1 Keys: K_fwd_1, K_bwd_1

    C->>E: RELAY_DATA(C1, Enc_1[EXTEND(Middle_ID, Noise_NK_msg1_Middle)])
    E->>M: TCP + Noise_IK (Link 2) + CREATE(cid=C2, msg1_Middle)
    M-->>E: CREATED(cid=C2, msg2_Middle)
    E-->>C: RELAY_DATA(C1, Enc_1_bwd[EXTENDED(msg2_Middle)])
    Note over C,M: Shared Hop 2 Keys: K_fwd_2, K_bwd_2 (Entry cannot decrypt)

    C->>E: RELAY_DATA(C1, Enc_1[Enc_2[EXTEND(Exit_ID, Noise_NK_msg1_Exit)]])
    E->>M: RELAY_DATA(C2, Enc_2[EXTEND(Exit_ID, msg1_Exit)])
    M->>X: TCP + Noise_IK (Link 3) + CREATE(cid=C3, msg1_Exit)
    X-->>M: CREATED(cid=C3, msg2_Exit)
    M-->>E: RELAY_DATA(C2, Enc_2_bwd[EXTENDED(msg2_Exit)])
    E-->>C: RELAY_DATA(C1, Enc_1_bwd[Enc_2_bwd[EXTENDED(msg2_Exit)]])
    Note over C,X: Shared Hop 3 Keys: K_fwd_3, K_bwd_3
```

### 3.2 Forward Request Lifecycle

```mermaid
flowchart TD
    A["Client builds InnerPayload (request_id, target_host:port, data)"] --> B["Encrypt layer 3 (K_fwd_3, seq3)"]
    B --> C["Encrypt layer 2 (K_fwd_2, seq2)"]
    C --> D["Encrypt layer 1 (K_fwd_1, seq1)"]
    D --> E["Send on Noise_IK Link 1 (cid=C1)"]
    E --> F["Entry peels K_fwd_1 -> forwards on C2"]
    F --> G["Middle peels K_fwd_2 -> forwards on C3"]
    G --> H["Exit peels K_fwd_3 -> reassembles request"]
    H --> I{"SSRF & Policy Check (Deny RFC1918 / Loopback)"}
    I -- "Denied" --> J["Return sanitized ERROR cell"]
    I -- "Allowed" --> K["Exit resolves DNS & connects to Destination"]
```

### 3.3 Response Forwarding Lifecycle

```mermaid
sequenceDiagram
    participant D as Destination
    participant X as Exit Relay
    participant M as Middle Relay
    participant E as Entry Relay
    participant C as Client

    D-->>X: Bounded Response (<= 64 KiB)
    X->>X: Fragment + Wrap with K_bwd_3 (seq_b3)
    X-->>M: RELAY_DATA(cid=C3, Enc_b3[InnerResp])
    M->>M: Lookup C3 -> C2, Wrap with K_bwd_2 (seq_b2)
    M-->>E: RELAY_DATA(cid=C2, Enc_b2[Enc_b3[InnerResp]])
    E->>E: Lookup C2 -> C1, Wrap with K_bwd_1 (seq_b1)
    E-->>C: RELAY_DATA(cid=C1, Enc_b1[Enc_b2[Enc_b3[InnerResp]]])
    C->>C: Peel K_bwd_1, K_bwd_2, K_bwd_3 -> Reassemble Response
```

### 3.4 Relay Failure & Teardown Handling

```mermaid
flowchart TD
    F1["Trigger: TCP EOF / Timeout / AEAD Tag Fail / Sequence Mismatch"] --> F2["Lookup CircuitRoute in Relay CircuitTable"]
    F2 --> F3["Remove CircuitRoute & Zeroize K_fwd, K_bwd"]
    F3 --> F4{"Has Opposite Peer?"}
    F4 -- "Yes" --> F5["Enqueue DESTROY(reason) to opposite cid"]
    F4 -- "No (Client/Exit end)" --> F6["Fail pending RequestId with RelayError"]
    F5 --> F7["Downstream/Upstream peers also purge & zeroize"]
    F6 --> F8["Phase 5: Evict failed relay & build fresh circuit"]
```

---

## 4. State Management

- **Stateless Framing vs. Stateful Circuits:** `protocol` is completely stateless. Relays store zero disk state for circuits. All circuit routing (`CircuitId -> { keys, seq_counters, bounded_tx_channel, last_active }`) lives exclusively in bounded RAM and vanishes on `DESTROY` or process restart.
- **Backpressure Invariant:** Each circuit allocates a bounded `tokio::sync::mpsc::channel(64)`. If a downstream peer stalls and fills the 64-cell queue, the relay enforces a short send timeout (`2s`) and tears down the stalled circuit rather than buffering unbounded memory.
