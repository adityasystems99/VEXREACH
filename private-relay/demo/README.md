# Private-Relay v0.1 — Local Multi-Process Demo Guide

This demo runs **5 separate Windows OS processes** communicating exclusively over localhost TCP sockets with full Noise links (`Noise_IK`) and 3-hop onion cryptography (`Noise_NK` + `ChaCha20-Poly1305`):

```text
relay-client.exe ──▶ relay-entry.exe (:9101) ──▶ relay-middle.exe (:9102) ──▶ relay-exit.exe (:9103) ──▶ demo-dest.exe (:9000)
```

> **Security & Config Note:** This is a local engineering demonstration (`allow_loopback_for_test = true`, explicit `allowed_targets = ["127.0.0.1:9000"]` at Exit). Static template files live in [demo/configs/](./configs/), while fresh ephemeral keys and active runtime TOML files (`entry.toml`, `middle.toml`, `exit.toml`, `client.toml`) are generated locally into `demo/generated/` (gitignored) and are NEVER committed to the repository. Do NOT reuse demo configs/keys in production. `start-demo.ps1` launches the three relays with `--log-level debug` into `demo/logs/` so `run-demo.ps1` verifies `STATUS=READY`, `"relay node started"`, and `"circuit hop established"` across all three independent OS processes without logging IPs, keys, or payloads.

---

## 1. Prerequisites

- Windows 10/11 with PowerShell 5.1+ / PowerShell 7+
- Rust toolchain `rustc 1.93.1+` & `cargo` (MSVC target `x86_64-pc-windows-msvc` + VS2022 linker)
- Workspace dependencies already cached cleanly (`--offline`)

---

## 2. One-Command Automated Demo (Recommended)

From `private-relay\`:

```powershell
.\demo\run-demo.ps1 -AutoStartStop
```

Or manage process lifecycle manually in 3 steps:

```powershell
# 1. Generate fresh keys + build binaries + launch demo-dest, exit, middle, entry OS processes:
.\demo\start-demo.ps1 -RotateKeys

# 2. Execute client requests across health, medium, exact 64 KiB, oversized, slow, redirect & policy denial:
.\demo\run-demo.ps1

# 3. Tear down all 4 background server processes:
.\demo\stop-demo.ps1
```

---

## 3. Manual Multi-Terminal Walkthrough (Exact Commands)

### Step 1: Build All Standalone Binaries

```powershell
cd private-relay
cargo build --offline --bins
```

Produced binaries under `target\debug\`:
- `demo-dest.exe`
- `relay-keygen.exe`
- `relay-exit.exe`
- `relay-middle.exe`
- `relay-entry.exe`
- `relay-client.exe`

### Step 2: Generate Fresh Local Identities (Never Committed)

```powershell
.\target\debug\relay-keygen.exe --out-dir .\demo\generated --allow-target 127.0.0.1:9000
```

Optionally validate all configs beforehand (`--check-only`):

```powershell
.\target\debug\demo-dest.exe --config .\demo\configs\destination.toml --check-only
.\target\debug\relay-exit.exe --config .\demo\generated\exit.toml --check-only
.\target\debug\relay-middle.exe --config .\demo\generated\middle.toml --check-only
.\target\debug\relay-entry.exe --config .\demo\generated\entry.toml --check-only
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --check-only
```

### Step 3: Start Processes in 4 Separate Terminals

**Terminal 1 (Controlled Destination):**
```powershell
.\target\debug\demo-dest.exe --config .\demo\configs\destination.toml
```

**Terminal 2 (Exit Relay):**
```powershell
.\target\debug\relay-exit.exe --config .\demo\generated\exit.toml
```

**Terminal 3 (Middle Relay):**
```powershell
.\target\debug\relay-middle.exe --config .\demo\generated\middle.toml
```

**Terminal 4 (Entry Relay):**
```powershell
.\target\debug\relay-entry.exe --config .\demo\generated\entry.toml
```

### Step 4: Execute Requests from Terminal 5 (`relay-client`)

```powershell
# Health check:
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --url http://127.0.0.1:9000/health

# Medium multi-chunk (12 KiB):
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --url http://127.0.0.1:9000/medium

# Exact 64 KiB (65,536B) boundary:
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --target 127.0.0.1:9000 --data-bytes 65536
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --url http://127.0.0.1:9000/max-64kib

# Oversized reject (65,537B rejected client-side; /oversized aborted by Exit):
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --target 127.0.0.1:9000 --data-bytes 65537
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --url http://127.0.0.1:9000/oversized

# Exit SSRF / allowlist enforcement (unlisted port blocked cleanly):
.\target\debug\relay-client.exe --config .\demo\generated\client.toml --url http://127.0.0.1:9099/health
```

### Step 5: Clean Shutdown

Press `Ctrl+C` in Terminals 4 → 3 → 2 → 1 (each relay triggers `handle.shutdown().await` and emits `STATUS=STOPPED`), or run `.\demo\stop-demo.ps1`.

---

## 4. Troubleshooting

- **`connection: FAILED` or refused on `:9101/:9102/:9103`:** Confirm terminals were started in dependency order (`demo-dest` → `exit` → `middle` → `entry`) and no firewall/antivirus or old demo PID holds those ports (`.\demo\stop-demo.ps1`).
- **`REMOTE_ERROR(PolicyDenied)` on loopback targets:** Confirm `exit.toml` has both `allow_loopback_for_test = true` AND the exact `host:port` inside `allowed_targets`.
- **`invalid relay configuration` after manual edit:** Check that `role` matches the binary (`relay-entry`, `relay-middle`, `relay-exit`), `public_key_hex` matches `private_key_hex`, and `allowed_next_peers` strictly points `entry -> middle -> exit`.
