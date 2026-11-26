# Threat Model — Private-Relay Protocol (`v0.1`)

> **Core Invariant:** Multi-hop layered encryption hides *payloads* and breaks *single-relay linkability* between sender and destination. **It does NOT guarantee anonymity** against traffic analysis, colluding endpoints, or endpoint compromise.

---

## 1. Threat Matrix & Security Analysis

### Threat 1 — Passive Network Observer (Local ISP / IXP / Global Eavesdropper)
1. **Attack Scenario:** Adversary passively records encrypted TCP packets on `Client ↔ Entry` and simultaneously (or selectively) taps `Exit ↔ Destination`.
2. **Potential Impact:**
   - Single-link tap (`Client ↔ Entry` only): Sees client IP, connection duration, and total cell count, but **not** destination or payload.
   - Dual-ended tap (`Client ↔ Entry` + `Exit ↔ Destination`): Correlates packet burst timings and request/response byte counts to link Client IP to Destination with high confidence.
3. **Required Security Property:** Confidentiality of payloads/destinations against single-point wiretaps; honest disclosure of dual-ended correlation risk.
4. **Proposed Mitigation:** Fixed-size `600`-byte Noise link frames conceal internal handshake vs. data cell types; end-to-end TLS from Client to Destination protects application contents even past Exit.
5. **Remaining Limitations:** **Unmitigated against dual-ended timing and volume correlation.** No dummy cover traffic or mix delays exist in `v0.1`.
6. **How to Test the Mitigation:** Automated packet-size invariance test asserting that `CREATE`, `EXTEND`, and `RELAY_DATA` cells all serialize to identical `582`-byte outer plaintext (`600`-byte complete link wire record including `2B` prefix + `16B` MAC), plus correlation visibility notes across Entry and Exit captures.

---

### Threat 2 — Malicious Entry Relay
1. **Attack Scenario:** Adversary operates the `Entry` node and attempts to learn the final destination, read client payloads, impersonate `Middle`, or redirect circuits to an attacker-controlled `Exit`.
2. **Potential Impact:** Entry already knows the client's source IP; if it could decrypt inner layers or MITM `EXTEND` handshakes, total privacy fails.
3. **Required Security Property:** End-to-hop confidentiality (`K_fwd_2`, `K_fwd_3`) and cryptographic authentication of `Middle` against `Entry` MITM.
4. **Proposed Mitigation:** Telescopic `Noise_NK` handshake authenticates `Middle`'s static `X25519` public key known to Client; Entry cannot forge `CREATED`/`EXTENDED` for `Middle` without `Middle`'s private key.
5. **Remaining Limitations:** Entry still sees **client source IP**, circuit lifetime, and packet cadence. Entry can drop/throttle circuits (DoS) or mount active timing watermarking (modulating packet inter-arrival delays) if colluding with Exit.
6. **How to Test the Mitigation:** Adversarial unit/integration test replacing `Middle`'s key with an Entry-controlled spoofed keypair inside `EXTEND` — Client **must** reject `EXTENDED` handshake and tear down circuit (`NoiseDecryptError`).

---

### Threat 3 — Malicious Exit Relay
1. **Attack Scenario:** Adversary operates `Exit`, sees outbound traffic to Destination, and attempts to: (a) read unencrypted payloads, (b) learn client IP, (c) tamper with responses, or (d) abuse Exit for SSRF into private/localhost networks (`127.0.0.1`, `169.254.169.254`).
2. **Potential Impact:** Credential/plaintext sniffing on non-TLS destinations; cloud metadata theft / internal LAN pivoting via SSRF.
3. **Required Security Property:** Zero client identity leakage to Exit; integrity on response payloads; strict outbound SSRF network isolation.
4. **Proposed Mitigation:**
   - Circuit protocol carries zero client IP/headers (`CircuitId` is strictly link-local to `Middle ↔ Exit`).
   - Exit validates resolved Destination IPs against an explicit deny list (loopback, RFC1918, link-local `169.254.0.0/16`, IPv6 `::1`/`fc00::/7`/`fe80::/10`) before `TcpStream::connect` (`v0.1` loopback test harness overrides this strictly behind an explicit `allow_loopback_for_test` flag disabled by default!).
   - Clients are instructed to wrap HTTP/API payloads in **end-to-end TLS** (`https://`) to Destination so Exit never sees plaintext.
5. **Remaining Limitations:** Plaintext (`http://`) destination requests are readable by Exit. A malicious Exit can inject malicious HTTP responses to plaintext traffic or drop connections.
6. **How to Test the Mitigation:** Automated Exit SSRF unit tests attempting requests to `127.0.0.1:80`, `169.254.169.254:80`, `10.0.0.1:80`, `[::1]:80` under default config — Exit **must** deny with `ExitPolicyError::PrivateAddressDenied` without opening any socket.

---

### Threat 4 — Colluding Relays (`Entry + Exit` or `Entry + Middle + Exit`)
1. **Attack Scenario:** One organization or attacker compromises/operates both `Entry` and `Exit` (or receives traffic from a compromised `Client` path where both endpoints belong to the attacker).
2. **Potential Impact:** **Complete sender-to-destination linkage** via timing/sequence correlation (`Entry` learns client IP; `Exit` learns destination + plaintext if non-TLS).
3. **Required Security Property:** Diversity of relay operators and network topology; clear operator accountability.
4. **Proposed Mitigation:** In `Phase 5` route selection, enforce **operator-ID uniqueness** and **`/24` IPv4 / `/48` IPv6 subnet disjointness** across `Entry`, `Middle`, and `Exit` (never select two relays from one operator or prefix). Use `3` hops rather than `2` so `Middle` breaks direct `Entry ↔ Exit` handshake correlation.
5. **Remaining Limitations:** Sybil attackers registering distinct fake identities across separate cloud VPS IPs can still defeat naive subnet checks without trusted vetting (`Sybil resistance` remains an open directory governance challenge).
6. **How to Test the Mitigation:** Unit tests for route selector (`Phase 5`) asserting candidate sets containing duplicate operator IDs or matching `/24` prefixes are rejected cleanly.

---

### Threat 5 — Malicious Destination
1. **Attack Scenario:** Destination server attempts to trace the real client IP, return oversized multi-gigabyte responses (OOM DoS on Exit/Client), or hang sockets indefinitely (Slowloris).
2. **Potential Impact:** Exhaustion of Exit memory/file descriptors; deanonymization if client leaks identifiers inside application payloads (`User-Agent`, cookies, client-side callbacks).
3. **Required Security Property:** Exit isolates Client IP; bounded read size and strict I/O timeouts protect Exit and circuit buffers.
4. **Proposed Mitigation:** Outbound connections originate strictly from Exit's IP; Exit enforces `max_response_bytes = 65_536` and `destination_io_timeout = 10s`.
5. **Remaining Limitations:** Application-layer tracking (auth tokens, browser fingerprints, client-triggered WebRTC/external asset fetches outside the tunnel) will still expose the client if an app embeds identifying tokens.
6. **How to Test the Mitigation:** Integration test pointing Exit at a mock malicious Destination sending `5 MiB` of streaming bytes or sleeping for `30s` — Exit **must** abort cleanly with `PayloadTooLarge` / `Timeout` within bounded memory.

---

### Threat 6 — Replay, Tampering & Tagging Attackers
1. **Attack Scenario:** On-path attacker captures encrypted `RELAY_DATA` frames and injects duplicates, swaps forward/backward directions, or flips ciphertext bits to see where downstream circuits fail ("tagging attack").
2. **Potential Impact:** Desynchronized cipher streams, duplicate request execution at Destination, or circuit-path oracle via tagging.
3. **Required Security Property:** Strict message integrity, replay rejection, and directional key separation at every single hop.
4. **Proposed Mitigation:**
   - Outer `Noise_IK` link authenticates every frame across adjacent peers.
   - Inner `ChaCha20-Poly1305` uses separated directional keys (`K_fwd_i` vs `K_bwd_i`) and strict monotonic `seq: u64` counters per circuit direction (`seq == expected_seq`).
   - Any authentication error at hop `i` immediately drops the circuit (`DESTROY`) without leaking which byte failed.
5. **Remaining Limitations:** Stopping a frame at hop `i` prevents *tagging propagation*, though a colluding downstream node notices the circuit tore down prematurely.
6. **How to Test the Mitigation:** Crypto unit tests verifying: (a) flipping 1 ciphertext bit fails decryption immediately; (b) replaying a previously valid frame `(seq - 1)` is rejected; (c) feeding a forward-encrypted cell into the backward decryptor fails.

---

### Threat 7 — Denial-of-Service (DoS) & Resource Exhaustion Attackers
1. **Attack Scenario:** Attacker floods Entry with thousands of `CREATE` CPU-expensive ECDH handshakes, opens `10,000` half-built circuits, or sends slowly without reading responses (`backpressure stall`).
2. **Potential Impact:** CPU starvation, unbounded memory growth, legitimate user starvation.
3. **Required Security Property:** Graceful degradation under bounded memory and bounded per-IP concurrency.
4. **Proposed Mitigation:**
   - Per-IP connection & circuit cap at Entry (`max_circuits_per_peer_ip = 16`).
   - Global circuit ceiling per relay (`max_concurrent_circuits = 1024`).
   - Fixed bounded `tokio::sync::mpsc::channel(64)` per circuit + handshake timeout (`5s`) + idle circuit eviction (`120s`).
5. **Remaining Limitations:** Volumetric Layer-3/4 UDP/SYN floods against a relay's public IP require kernel/OS firewall (`nftables`/SYN cookies) or upstream DDoS mitigation beyond application-layer Rust code.
6. **How to Test the Mitigation:** Concurrency stress test (`Phase 7`) opening `max_concurrent_circuits + 50` circuits concurrently — relay **must** reject excess circuits cleanly without panic or unbounded RSS growth.

---

### Threat 8 — Compromised Client Device
1. **Attack Scenario:** Malware or misconfigured application on the user's machine logs keys, resolves DNS locally before forwarding, or bypasses the Private-Relay client entirely.
2. **Potential Impact:** Total loss of destination privacy and payload confidentiality.
3. **Required Security Property:** Explicit trust boundary statement; client memory hygiene where practical.
4. **Proposed Mitigation:** Zeroize ephemeral circuit secrets on drop (`zeroize` crate); provide explicit client API taking target **domain string (`host:port`)** rather than pre-resolved IPs so DNS stays inside the tunnel.
5. **Remaining Limitations:** **No network protocol can protect against a compromised endpoint OS/client binary.** If the user's device is compromised, all security properties fail.
6. **How to Test the Mitigation:** Client unit test asserting target hostnames are serialized as UTF-8 domains inside `InnerPayload::Begin` without invoking `std::net::ToSocketAddrs` on the Client.

---

### Threat 9 — Compromised Relay Machine
1. **Attack Scenario:** Attacker gains root access on a single relay host (`Entry`, `Middle`, or `Exit`), inspecting process RAM (`circuit_table`) and disk (`relay.toml`, keys).
2. **Potential Impact:** Access to that relay's active per-hop keys (`K_fwd_i`, `K_bwd_i`) and static identity/onion keys; visibility into whatever metadata that single hop handles.
3. **Required Security Property:** Blast-radius containment (compromising one relay reveals **only** that relay's local adjacency, never full `Client ↔ Destination` pairs or past closed sessions).
4. **Proposed Mitigation:**
   - Ephemeral `Noise_NK` handshakes give **forward secrecy** for past destroyed circuits once keys are zeroized.
   - Least-privilege OS service isolation (non-root user, minimal filesystem permissions on key files, disabled swap/core dumps in deployment guide `Phase 8`).
   - Zero plaintext/IP access logs on disk.
5. **Remaining Limitations:** Live RAM inspection on a running compromised `Entry` or `Exit` exposes active connections crossing that specific machine. Also, stealing `onion.key` allows impersonation until rotated/revoked in the directory (`Phase 5`).
6. **How to Test the Mitigation:** Verify via code audit and unit tests that `DESTROY` drops and zeroizes session `ChaCha20` key structs, and verify log output from a full 3-hop run contains zero client IPs or target domains.
