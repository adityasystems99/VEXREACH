# Known Issues, Limitations & Open Risks (`KNOWN_ISSUES.md`)

This file tracks unresolved technical limitations, open security questions, and known design constraints—never hiding gaps behind marketing wording.

---

| ID | Category | Description | Severity | Mitigation / Plan |
| :--- | :--- | :--- | :--- | :--- |
| **`KI-01`** | Traffic Analysis | Dual-ended passive observation (`Client↔Entry` + `Exit↔Destination`) can correlate request timing and cell volume despite 3-hop AEAD. | **High (Fundamental)** | Documented honestly as non-defeated in `v0.1`; future mix delays/cover padding would be needed to resist timing correlation. |
| **`KI-02`** | Collusion / Sybil | A single operator running multiple relays or controlling `Entry + Exit` breaks sender-destination separation. | **High** | Enforce operator-ID & `/24`/`/48` prefix separation in `Phase 6` route selector; directory governance remains required against Sybil operators. |
| **`KI-03`** | Packet Length / Hop Role | Nested `ChaCha20-Poly1305` strips `24B/hop` inside the `584B` link frame, revealing hop index (`1/2/3`) to adjacent honest relays in our 3-role topology. | **Medium (Design Trade-off)** | Acceptable for fixed `Entry → Middle → Exit` roles; variable `N`-hop anonymity requires Sphinx constant-size headers (`Deferred`). |
| **`KI-04`** | Transport | Multiplexing multiple circuits over a single TCP link can suffer head-of-line blocking under packet loss. | **Medium** | Measured in `Phase 8`; evaluate QUIC stream isolation only after TCP baseline metrics exist. |
| **`KI-05`** | SSRF / DNS Rebinding | Exit DNS lookup followed by separate `TcpStream::connect(hostname)` risks TOCTOU DNS rebinding to `127.0.0.1` / `169.254.169.254`. | **High (Design Guard)** | Exit implementation **must** resolve once, validate all IPs against deny list, and pass the validated `SocketAddr` directly to `TcpStream::connect`. |
| **`KI-06`** | Implementation | No Rust crates or automated security tests exist yet (`Phase 3–4` pending). | **Baseline** | Begin incrementally with `crates/protocol` and `crates/crypto` unit tests before building networking loops. |
