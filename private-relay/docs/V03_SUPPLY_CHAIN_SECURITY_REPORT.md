# VEXREACH Private Relay v0.3 — Supply-Chain, Build & Container Security Report (Track 4)

**Project:** VEXREACH Private Relay (Unaudited Research Prototype)  
**Scope:** `private-relay/` workspace dependencies, lockfile reproducibility, license compliance, container image provenance, and binary hardening  
**Status Summary:** Workspace lockfile & SPDX license audit `VERIFIED OFFLINE`; offline reproducible `--locked` binary & Docker image build `VERIFIED` (`task-5905`); automated advisory database scanning (`cargo-audit`, `cargo-deny`, live OSV query) `BLOCKED` / `NOT VERIFIED` (tools & advisory DB unavailable offline).

---

## 1. Cargo Workspace & Dependency Graph Verification

Observed directly from `Cargo.toml`, `Cargo.lock`, `cargo metadata --offline --no-deps`, and `cargo tree --offline --workspace` under `rustc 1.93.1` / `cargo 1.93.1`:

- **Total `Cargo.lock` `[[package]]` entries:** `81` (`6` internal workspace crates + `75` third-party registry crates representing `74` unique external crate names).
- **Direct external workspace dependencies (`Cargo.toml`):**
  - Cryptography & memory wiping: `snow 0.9.6`, `chacha20poly1305 0.10.1`, `hkdf 0.12.4`, `sha2 0.10.9`, `zeroize 1.9.2` (`features = ["derive"]`), `rand 0.8.8`
  - Async runtime & serialization: `tokio 1.54.1` (`rt-multi-thread`, `macros`, `net`, `io-util`, `sync`, `time`, `signal`), `serde 1.0.229` (`derive`), `toml 0.8.23`, `tracing 0.1.44`
- **Git / external path dependencies:** `0` outside `crates/*`.
- **First-party `unsafe` code:** `0` occurrences across `crates/*/src/*.rs` (inspected across all 6 workspace crates).
- **Duplicate crate version check (`cargo tree --offline --workspace --duplicates`):**
  - Only duplicate across the entire normal dependency graph: `syn v2.0.119` (build-time proc-macro dependency of `curve25519-dalek-derive v0.1.1`, `tracing-attributes v0.1.31`, and `zeroize_derive v1.5.0`) alongside `syn v3.0.10` (build-time proc-macro dependency of `serde_derive v1.0.229` and `tokio-macros v2.7.2`).
  - **Zero duplicate runtime crates** linked into workspace binaries.

### 1.1 Exact Transitive License Inventory (`cargo tree --edges normal --format '{p} :: {l}'`)

Every resolved normal dependency carries a permissive OSI-approved SPDX license expression:

| SPDX License Expression | Representative Crates |
|---|---|
| `MIT` | Workspace crates (`private-relay-*`), `tokio 1.54.1`, `tokio-macros 2.7.2`, `tracing 0.1.44`, `tracing-core 0.1.36`, `tracing-attributes 0.1.31`, `bytes 1.12.2`, `mio 1.2.5`, `generic-array 0.14.7`, `winnow 0.7.15` |
| `Apache-2.0 OR MIT` / `MIT OR Apache-2.0` | `snow 0.9.6`, `chacha20poly1305 0.10.1`, `chacha20 0.9.1`, `poly1305 0.8.0`, `hkdf 0.12.4`, `hmac 0.12.1`, `sha2 0.10.9`, `digest 0.10.7`, `aead 0.5.2`, `cipher 0.4.4`, `aes-gcm 0.10.3`, `aes 0.8.4`, `ctr 0.9.2`, `ghash 0.5.1`, `polyval 0.6.2`, `blake2 0.10.6`, `zeroize 1.9.2`, `zeroize_derive 1.5.0`, `rand 0.8.8`, `rand_core 0.6.4`, `rand_chacha 0.3.1`, `getrandom 0.2.17`, `serde 1.0.229`, `toml 0.8.23`, `socket2 0.6.5`, `syn 2.0.119` & `3.0.10` |
| `BSD-3-Clause` | `curve25519-dalek 4.1.3`, `subtle 2.6.1` |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | `zerocopy 0.8.66` |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | `unicode-ident 1.0.27` |
| `MIT/Apache-2.0` | `curve25519-dalek-derive 0.1.1` |

*(No copyleft `GPL`/`AGPL`, `LGPL`, `SSPL`, or proprietary licenses appear in the normal workspace build.)*

---

## 2. Dependency Feature & Minimality Review

1. **`snow 0.9.6` Default Resolver Pull (`default-features = true`):**
   - Because `snow = "0.9"` uses default features, `Cargo.lock` resolves `aes 0.8.4`, `aes-gcm 0.10.3`, `ctr 0.9.2`, `ghash 0.5.1`, `polyval 0.6.2`, `blake2 0.10.6`, and `universal-hash 0.5.1` even though Private Relay's protocol uses exclusively `Noise_NK_25519_ChaChaPoly_SHA256` and `Noise_XX_25519_ChaChaPoly_SHA256`.
   - **Status (`VERIFIED OFFLINE` behavior, `PROPOSED` improvement):** Track 1 mitigated the security hazard of `snow`'s default resolver types by wrapping handshake/cipher/hash primitives in `ZeroizingCryptoResolver` (`crates/crypto/src/keys.rs`). Reducing Cargo feature surface (disabling unused `aes-gcm`/`blake2` resolvers via `default-features = false, features = ["ring-resolver"]` or minimal crypto features in a future lockfile refresh) remains `PROPOSED` to avoid breaking offline lockfile constraints in v0.3.
2. **`digest 0.10.7` / `sha2 0.10.9` Without `zeroize` Feature:**
   - `sha2` / `digest` omit the optional `zeroize` Cargo feature in `Cargo.lock`. Track 1 compensated via explicit `Hash::reset()` in `ZeroizingHash::drop` (verifying `digest_resets` counters in `key_lifecycle_tests.rs`).
3. **Separate Unlocks on `fuzz/` (`exclude = ["fuzz"]`):**
   - `fuzz/Cargo.toml` requires `libfuzzer-sys` + nightly `-Z sanitizer=address`, excluded from the offline runtime workspace (`exclude = ["fuzz"]`), so fuzzing dependencies never pollute runtime binaries or `Cargo.lock`.

---

## 3. Reproducible Build & Artifact Hygiene Verification

| Verification | Outcome | Classification | Notes |
|---|---|---|---|
| `cargo check --offline --locked --bins` | Passed (exit `0`) | `VERIFIED OFFLINE` | Enforces `Cargo.lock` byte-for-byte match |
| `cargo test --offline --workspace` | Passed (`72 passed; 0 failed`) | `VERIFIED OFFLINE` | Executed against hardened v0.3 workspace |
| `docker compose build` (`cargo build --release --locked --bins`) | Passed in `16.4s` (BuildKit layer build) | `VERIFIED` | Produces stripped ELF64 x86_64 binaries inside container |
| `git ls-files` secret / binary hygiene check | `0` keys, `.pem`, `.exe`, `.dll`, `.so`, `.pdb` tracked | `VERIFIED OFFLINE` | Confirmed against repository index |
| `cargo-audit` / `cargo-deny` / RustSec `advisory-db` | Not installed; local DB absent (`advisory-db_exists=False`); crates.io TLS blocked in sandbox (`SEC_E_UNTRUSTED_ROOT`) | `BLOCKED` / `NOT VERIFIED` | Must be executed in CI / online environment with RustSec DB |

---

## 4. Container Image Security Audit (`private-relay:v0.1`)

Inspected directly after the v0.3 rebuild (`docker image inspect`, `docker history`, container filesystem probe, and `dpkg-query`):

- **Image ID & Size:** `sha256:9b3e83a667c84ba59e765838839423ba43c6a94d76926d44f53ee35f11fe3ed6`, image metadata `Size = 32,911,260` bytes (~31.4 MiB compressed manifest/layer sum; uncompressed `debian:bookworm-slim` base layer reported `85.3 MB` in `docker history`).
- **Two-Stage Build Separation (`Dockerfile`):**
  - Stage 1 (`rust:1.93.1-slim-bookworm`): builds dummy dependency layer first, compiles real workspace via `cargo build --release --locked --bins`, and strips all six binaries (`demo-dest` `1.16 MB`, `relay-keygen` `934 kB`, `relay-exit` `2.17 MB`, `relay-middle` `2.17 MB`, `relay-entry` `2.17 MB`, `relay-client` `1.74 MB`). Zero Rust compiler/Cargo toolchains are copied into Stage 2.
  - Stage 2 (`debian:bookworm-slim`): creates unprivileged `relay` user/group (`10001:10001`, shell `/usr/sbin/nologin`), sets `/app` and `/cfg/{entry,middle,exit,client}` permissions (`0750`), installs immutable `--chmod=0555` binaries and `--chmod=0444` `/app/destination.toml`, and sets `USER 10001:10001`.
- **Zero Embedded Keys Verified:** Container shell probe of `/cfg`, `/cfg/entry`, `/cfg/middle`, `/cfg/exit`, `/cfg/client` after build confirms all key/config directories are completely empty at image build time; only `demo/configs/destination.docker.toml` (`50 bytes`) is baked into `/app/destination.toml`.
- **Container Package Inventory (`dpkg-query` = `88` Debian 12 Bookworm packages):**
  - Core C runtime & utilities: `libc6=2.36-9+deb12u14`, `libc-bin=2.36-9+deb12u14`, `libstdc++6=12.2.0-14+deb12u1`, `libgcc-s1=12.2.0-14+deb12u1`, `libseccomp2=2.5.4-1+deb12u1`, `libcap2=1:2.66-4+deb12u3+b1`, `zlib1g=1:1.2.13.dfsg-1`, `tzdata=2026f-0+deb12u1`.
  - Package/shell utilities present from `debian:bookworm-slim`: `apt=2.6.2`, `bash=5.2.15-2+b13`, `dash=0.5.12-2`, `dpkg=1.21.23`, `perl-base=5.36.0-7+deb12u4`, `tar=1.34+dfsg-1.2+deb12u1`, `findutils=4.9.0-4`, `coreutils=9.1-1`, `gpgv=2.2.40-1.1+deb12u2`, `libgnutls30=3.7.9-2+deb12u7`, `libgcrypt20=1.10.1-3+deb12u1`, `libsystemd0=252.39-1~deb12u2`, etc. (zero compilers, `curl`, `wget`, `openssh`, `python`, or `sudo` installed).
  - **Hardening Observation (`PROPOSED`):** Because `debian:bookworm-slim` retains `apt`, `bash`, `dash`, `tar`, and `perl-base` (`88` total packages), a post-exploitation container breakout/shell-exec attacker finds standard Unix shells/tar present despite `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, and `capabilities.drop: ["ALL"]`. Migrating runtime containers (other than debug probes) to `gcr.io/distroless/cc-debian12:nonroot` or a minimal musl scratch image would remove all 88 Debian userspace packages once probe ergonomics are decoupled.
- **Third-Party Observability & Init Images (`k8s/`):**
  - Pinned tags (not floating `:latest`): `alpine/kubectl:1.34.1` (`keygen-job.yaml`), `prom/prometheus:v2.53.0` (`observability-prometheus.yaml`), `grafana/grafana:11.1.0` (`observability-grafana.yaml`). **Limitation:** Tags are mutable upstream; digest pinning (`@sha256:...`) and SBOM / Cosign provenance attestation are `PROPOSED` before shared-cluster deployment.

---

## 5. Summary Risk & Remediation Backlog

1. **`BLOCKED` — Offline RustSec CVE Scan:** Run `cargo audit` and `cargo deny check advisories licenses bans sources` in CI against live RustSec advisory DB before any external deployment.
2. **`PROPOSED` — Cargo Feature Minimization:** Switch `snow` features to eliminate unused AES-GCM / BLAKE2 codegen and enable `zeroize` on digest crates where supported.
3. **`PROPOSED` — Distroless Runtime + Image Digest Pinning:** Replace `debian:bookworm-slim` (`88` packages) with distroless nonroot runtime and pin `private-relay`, `prom/prometheus`, `grafana/grafana`, and `alpine/kubectl` by immutable SHA-256 digest with SBOM generation (Syft/CycloneDX).
