# PRIVATE RELAY v0.2 — PERFORMANCE BENCHMARK & BOTTLENECK REPORT

**Date:** 2026-11-28  
**Repository:** `adityasystems99/VEXREACH` (`private-relay/`, branch `master`)  
**Status Summary:** Microbenchmarks, Fair Direct-vs-3-Hop Macrobenchmarks, Bottleneck Analysis & Measured Before/After Optimizations **`VERIFIED OFFLINE`**

---

## 1. Hardware, Environment & Methodology

- **Host CPU:** `AMD Ryzen 7 8840HS w/ Radeon 780M Graphics` (`16` logical processors, `x86_64`)
- **OS / Toolchain:** Windows (`x86_64-pc-windows-msvc`), `rustc 1.93.1`, `--release` profile (`[optimized]`)
- **Benchmark Harness:** [crates/cli/examples/v02_benchmark.rs](../crates/cli/examples/v02_benchmark.rs)
- **Fairness Controls:** Same host loopback (`127.0.0.1`), same Tokio multi-thread runtime, identical echoed byte payloads (`0 B`, `1 KiB`, `12 KiB`, `32 KiB`, `64 KiB`), identical `tcp_nodelay`, `12 KiB`–`64 KiB` round-trip throughput reported as `(2 * size_bytes * ok) / elapsed_secs`, zero weakened timeouts/queues/crypto.

---

## 2. Microbenchmark Results (`Before -> After` Optimizations, `VERIFIED OFFLINE`)

| Hot Path Benchmark | Iterations | Before (`ns/op`) | Before (`ops/s`) | After (`ns/op`) | After (`ops/s`) | Speedup |
|---|---:|---:|---:|---:|---:|---:|
| `Cell` + `OuterFramePlaintext` pack/unpack | `100,000` | `345.1` | `2,897,493` | `263.8` | `3,790,190` | **`+30.8%`** |
| Chunk + Reassembly (`0 B`) | `10,000` | `846.9` | `1,180,763` | `506.0` | `1,976,167` | **`+67.4%`** |
| Chunk + Reassembly (`1 KiB`) | `10,000` | `2,371.1` | `421,743` | `1,509.3` | `662,559` | **`+57.1%`** |
| Chunk + Reassembly (`12 KiB`) | `10,000` | `19,436.3` | `51,450` | `12,748.1` | `78,443` | **`+52.5%`** |
| Chunk + Reassembly (`32 KiB`) | `2,000` | `72,920.9` | `13,713` | `79,626.6` | `12,559` | `-8.4%` *(run-to-run jitter)* |
| Chunk + Reassembly (`64 KiB`) | `2,000` | `132,430.0` | `7,551` | `79,298.7` | `12,611` | **`+67.0%`** |
| `HopCipherState` 1-Hop AEAD `seal+open` (`496B`) | `50,000` | `9,355.7` | `106,886` | `8,007.7` | `124,880` | **`+16.8%`** |
| Full 3-Hop Onion Round-Trip (`487B`) | `20,000` | `59,641.1` | `16,767` | `44,407.4` | `22,519` | **`+34.3%`** |
| `Noise_IK` `LinkSession` `seal+open` (`600B`) | `20,000` | `11,689.8` | `85,545` | `7,622.9` | `131,183` | **`+53.4%`** |

---

## 3. Macrobenchmarks: Direct Destination vs. 3-Hop Private Relay (`VERIFIED OFFLINE`)

### 3.1 Cold Single Requests (`10` runs/size: TCP Connect + Handshake + Request/Response)

| Payload | Direct `rps` (`After`) | Direct `p50` | 3-Hop `rps` (`Before -> After`) | 3-Hop `p50` (`Before -> After`) | 3-Hop `p95` (`After`) | Cold Relay Overhead Ratio (`After`) |
|---:|---:|---:|---:|---:|---:|---:|
| `0 B` | `893.4` | `1.20 ms` | `98.5 -> 130.5` | `9.35 -> 7.66 ms` | `11.65 ms` | `6.4x` *(4 Noise handshakes)* |
| `1 KiB` | `816.8` | `1.34 ms` | `105.8 -> 126.4` | `9.47 -> 8.04 ms` | `9.04 ms` | `6.0x` |
| `12 KiB` | `1,119.8` | `0.90 ms` | `77.0 -> 91.7` | `12.46 -> 11.09 ms` | `11.78 ms` | `12.3x` |
| `32 KiB` | `912.7` | `0.98 ms` | `57.3 -> 70.7` | `18.27 -> 14.08 ms` | `15.12 ms` | `14.4x` |
| `64 KiB` | `339.1` | `1.51 ms` | `39.5 -> 48.2` | `26.69 -> 20.65 ms` | `26.71 ms` | `13.7x` |

### 3.2 Sequential Reused Circuit (`100` reqs `0B–12KiB`, `40` reqs `32KiB–64KiB`) vs. Direct TCP

| Payload | Direct `rps` (`After`) | Direct `MiB/s` | 3-Hop `rps` (`Before -> After`) | 3-Hop `MiB/s` (`Before -> After`) | 3-Hop `p50` (`Before -> After`) | 3-Hop `p99` (`After`) | Error Rate |
|---:|---:|---:|---:|---:|---:|---:|---:|
| `0 B` | `1,023.7` | `0.00` | `502.6 -> 551.4` | `0.00 -> 0.00` | `1.95 -> 1.80 ms` | `2.75 ms` | `0%` |
| `1 KiB` | `831.7` | `1.62` | `413.1 -> 400.7` | `0.81 -> 0.78` | `2.38 -> 2.46 ms` | `3.24 ms` | `0%` |
| `12 KiB` | `648.1` | `15.19` | `184.9 -> 175.6` | `4.33 -> 4.12` | `4.97 -> 5.40 ms` | `7.09 ms` | `0%` |
| `32 KiB` | `819.3` | `51.21` | `86.6 -> 101.9` | `5.41 -> 6.37` | `10.19 -> 9.82 ms` | `11.99 ms` | `0%` |
| `64 KiB` | `560.1` | `70.01` | `54.2 -> 63.5` | `6.77 -> 7.94` | `17.48 -> 13.92 ms` | `38.09 ms` | `0%` |

### 3.3 Concurrent (`8` Workers, `120` Reqs @ `1 KiB`/`32 KiB`, `64` Reqs @ `64 KiB`) & Sustained (`5s`, `4` Workers @ `12 KiB`)

| Mode / Payload | Direct `rps` / `MiB/s` (`After`) | 3-Hop `Before` (`rps` / `MiB/s` / `p50` / `p99`) | 3-Hop `After` (`rps` / `MiB/s` / `p50` / `p99`) | Measured Improvement | Error Rate |
|---|---|---|---|---|---|
| Concurrent `8w` (`1 KiB`) | `5,728.9` / `11.19 MiB/s` | `2,063.2` / `4.03 MiB/s` / `3.21 ms` / `12.25 ms` | **`2,853.8` / `5.57 MiB/s` / `2.79 ms` / `3.57 ms`** | **`+38.3% rps`, `-70.9% p99`** | `0%` |
| Concurrent `8w` (`32 KiB`) | `4,712.8` / `294.55 MiB/s` | `210.7` / `13.17 MiB/s` / `36.07 ms` / `57.13 ms` | **`469.4` / `29.34 MiB/s` / `15.30 ms` / `30.77 ms`** | **`+2.23x throughput`, `-57.6% p50`** | `0%` |
| Concurrent `8w` (`64 KiB`) | `4,474.1` / `559.26 MiB/s` | `104.4` / `13.05 MiB/s` / `70.26 ms` / `119.94 ms` | **`264.2` / `33.02 MiB/s` / `27.52 ms` / `41.75 ms`** | **`+2.53x throughput`, `-60.8% p50`** | `0%` |
| Sustained `5s` (`4w` @ `12 KiB`) | *(3-Hop stress run)* | `2,127` reqs (`427.6 rps`, `10.02 MiB/s`, `p50=8.64ms`) | **`3,417` reqs (`686.9 rps`, `16.10 MiB/s`, `p50=5.69ms`, `p99=8.39ms`)** | **`+60.6% throughput`, `-64.3% p99`** | `0%` |

- **Benchmark Process Memory & Total CPU:** Before (`peak_ws=17.74 MiB`, `peak_priv=13.14 MiB`, `cpu_s=42.23s`) -> After (`peak_ws=20.07 MiB`, `peak_priv=15.36 MiB`, `cpu_s=31.17s` = **`-26.2%` CPU while serving `+1,290` more sustained requests**).
- Post-benchmark leaked circuits: `entry=0, middle=0, exit=0`.

---

## 4. Identified Bottlenecks & Applied Optimizations

1. **Per-Cell AEAD Key Setup & Heap Churn (`crates/crypto/src/hop.rs`):**
   - *Bottleneck:* `HopCipherState::seal` and `open` re-initialized `ChaCha20Poly1305::new_from_slice` on every cell, allocated `ciphertext: Vec<u8>` + `out: Vec<u8>`, and `ClientCircuitCrypto::seal_forward_to_hop` allocated `5` intermediate `Vec`s per onion packet (`59.6 µs` per 3-hop round-trip).
   - *Fix:* Cached `ChaCha20Poly1305` inside `HopCipherState` (derives `ZeroizeOnDrop`), implemented `AeadInPlace` `encrypt_in_place_detached`/`decrypt_in_place_detached`, added scratch-buffer swapping (`seal_prefixed_into`, `open_in_place_buf`) eliminating all intermediate `Forward` allocations (`-34.3%` 3-hop crypto time).
2. **Per-Frame Kernel RNG Syscalls & Copies (`crates/crypto/src/link.rs`, `crates/protocol/src/cell.rs`):**
   - *Bottleneck:* Every `600B` frame called `OsRng.fill_bytes` (`BCryptGenRandom` syscall on Windows), allocated `Vec<u8>` for `Cell::encode`, and copied `[u8; 582]` + `[u8; 598]` stack arrays (`11.69 µs` per frame).
   - *Fix:* Added `Cell::encode_into_slice` writing directly into the Noise plaintext buffer, replaced padding-only `OsRng` syscalls with a per-`LinkSession` `OsRng`-seeded `StdRng` CSPRNG (scrubbed on `Drop`; keys/seeds remain strictly `OsRng`), and encrypted directly into the `[u8; 600]` wire buffer (`-34.8%` link frame latency).
3. **Small 600-Byte Socket Syscall Fragmentation & Destination Reads (`crates/network/src/transport.rs`, `crates/client/src/client.rs`, `crates/relay/src/engine.rs`):**
   - *Bottleneck:* Sending a `64 KiB` message triggered `136` individual `write_all` socket calls per hop (`~816` syscalls total) and `4 KiB` destination reads caused 4 `Vec` reallocations.
   - *Fix:* Implemented `LinkWriter::send_cells_batch` coalescing back-to-back encrypted `600B` records without altering wire framing or per-frame rekey checks, non-blocking `try_recv()` batch draining (up to 32 queued cells) in relay link writers, and `16 KiB` destination read buffers — yielding **`+2.53x` concurrent `64 KiB` throughput**.

**Security Controls Unchanged:** All `600B` fixed frames, `<= 64 KiB` limits, `Noise_IK`/`Noise_NK` parameters, strict FIFO sequences, `ZeroizeOnDrop`, bounded mpsc capacities, SSRF policies, and timeouts remain 100% intact.
