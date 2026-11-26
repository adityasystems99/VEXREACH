# MVP Scope, Engineering Requirements & Targets — Private-Relay (`v0.1`)

---

## 1. Functional Requirements (`v0.1` Local Multi-Hop Milestone)

- **`FR-01` Binary Framing:** Serialize/deserialize fixed `600`-byte total on-wire Noise link frames (`2B` length `== 598` + `582B` plaintext + `16B` MAC) carrying `<= 580`-byte overlay cells (`9B` header + `<= 571B` body) with bounds checks rejecting oversized or malformed packets.
- **`FR-02` Peer Link Encryption:** Establish authenticated `Noise_IK` sessions over TCP between adjacent nodes (`Client↔Entry`, `Entry↔Middle`, `Middle↔Exit`).
- **`FR-03` Telescopic 3-Hop Circuit Build:** Client establishes independent `Noise_NK` forward/backward AEAD states (`K_fwd_i`, `K_bwd_i`) across `Entry → Middle → Exit`.
- **`FR-04` Bounded Request & Response Relaying (`Approved D-01`):** Forward request payloads up to `64 KiB` (`<= 140` chunks, `<= 487B` fragment per chunk, associated via `RequestId`) to a target `(host, port)`, receive Destination response (`<= 64 KiB`, `<= 140` chunks), and route replies cleanly back to Client. No long-lived multiplexed streams or `SENDME` flow control in `v0.1`.
- **`FR-05` Exit DNS & SSRF Enforcement:** Resolve destination domain names at `Exit` only; deny loopback/RFC1918/link-local IPs by default (`allow_loopback_for_test = false`).
- **`FR-06` Failure & Teardown Propagation:** Clean `DESTROY` propagation and immediate secret zeroization on AEAD failure, sequence replay, socket EOF, or timeout.
- **`FR-07` Configurable Local 3-Relay Testbed:** Launch 3 independent `relay` processes on separate `127.0.0.1` ports from TOML configs.
- **`FR-08` Automated Test Suite:** Unit tests (framing, AEAD, replay, SSRF) and local 3-hop E2E integration tests.

---

## 2. Non-Functional Requirements & Hard Resource Limits (`Phase 2` Baseline)

| Parameter | Initial `v0.1` Bound | Engineering Purpose |
| :--- | :--- | :--- |
| `WIRE_FRAME_BYTES` | `600` bytes (`2B len==598 + 582B plaintext + 16B MAC`) | Exact uniform packet size on TCP wire; bounds single-frame stack/heap allocation. |
| `MAX_MESSAGE_BYTES` | `65,536` bytes (`64 KiB`) | Prevents memory amplification per request/response on relays & client. |
| `MAX_CONCURRENT_CIRCUITS` | `1024` per relay (`16` per source IP at Entry) | Protects relay RAM & file descriptors under connection floods. |
| `CIRCUIT_QUEUE_CAPACITY` | `64` cells (`~38 KiB` per circuit) | Strict backpressure; slow readers cannot cause unbounded memory growth. |
| `HANDSHAKE_TIMEOUT` | `5s` | Reclaims half-open ECDH/Noise circuits quickly. |
| `IDLE_CIRCUIT_TTL` | `120s` | Frees unused circuits and triggers key zeroization. |
| `DESTINATION_IO_TIMEOUT` | `10s` | Prevents hung Destination sockets from pinning Exit tasks. |

---

## 3. Initial Targets & Assumptions (Targets Only — Not Measured Results)

* **Expected Local Prototype Workload (`Phase 4`):** `10`–`50` concurrent local circuits exchanging `1 KiB`–`64 KiB` HTTP/echo payloads over `127.0.0.1`.
* **Initial Performance Targets (To Benchmark in `Phase 8`, Never Claimed Ahead of Measurement):**
  - 3-hop circuit establishment latency overhead (`local loopback`): target `< 25 ms` p95.
  - Per-request forwarding overhead (`1 KiB` local payload across 3 hops): target `< 15 ms` p95.
  - Zero memory leaks across `1,000` sequential build → forward → `DESTROY` cycles.
* **Reliability Objective:** `100%` clean teardown and non-hanging error return to Client if `Middle` or `Exit` terminates mid-flight.
* **Deployment Assumptions (`v0.1`):** All nodes run on Windows `127.0.0.1:<port>` with static TOML keys; external firewalling/TLS/Docker multi-host isolation starts in `Phase 7–12`.

---

## 4. Explicit `v0.1` Privacy Boundary

- **Established once tested:** Single-hop cryptographic separation (`Entry` blinded to target/plaintext; `Middle` blinded to origin/target; `Exit` blinded to client IP), integrity against tampering, and deterministic FIFO replay protection.
- **Explicitly NOT established:** Resistance to passive dual-ended timing/burst correlation, collusion between `Entry` + `Exit`, Sybil resistance in open networks, or production anonymity guarantees.
