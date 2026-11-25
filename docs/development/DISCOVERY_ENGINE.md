# VEXReach Discovery Engine (Phase 3)

The **Discovery Engine** is VEXReach's ingestion, normalization, and evidence preservation layer. It inspects a local repository or directory without executing repository code, drives Aqua Security **Trivy** to produce both a **CycloneDX SBOM** and raw vulnerability scan results, normalizes packages and vulnerabilities into canonical Pydantic models, and persists raw artifacts alongside SHA-256 provenance hashes.

---

## 1. Architecture & Pipeline

```text
User CLI (`vexreach scan ./sample-app`)
   │
   ▼
TargetValidator (path existence, directory check, read permissions, manifest hints; zero execution)
   │
   ▼
DiscoveryOrchestrator
   │
   ▼
TrivyClient (isolated subprocess wrapper; `shell=False`, bounded output, strict timeouts)
   │
   ├─────────────────────────┐
   ▼                         ▼
CycloneDX SBOM Gen      Trivy Vuln Scan (`--scanners vuln`)
   │                         │
   ▼                         ▼
CycloneDXParser         TrivyReportParser
   │                         │
   └───────────┬─────────────┘
               ▼
       DiscoveryNormalizer
   (PURL, Severity, CVSS, Scope, Deduplication)
               │
               ▼
        DiscoveryResult
               │
               ▼
         EvidenceStore
   (raw-trivy-vuln.json, sbom-cyclonedx.json,
    discovery-assessment.json, provenance.json)
```

---

## 2. Module Responsibilities

| Module | Responsibility |
| :--- | :--- |
| `packages/core/engines/discovery/target_validator.py` | Validates local directories, verifies read permissions, prevents external symlink traversal, and detects manifest files strictly by filename without importing/executing code. |
| `packages/core/integrations/trivy/client.py` | Safe subprocess wrapper around `trivy`: locates binary, parses version, enforces timeouts, restricts scanners to `vuln`, checks exit codes, and rejects missing/empty/oversized/malformed output files. |
| `packages/core/integrations/trivy/parser.py` | Tolerant boundary parser for raw Trivy filesystem JSON. Rejects unrelated JSON payloads so invalid output is never mistaken for a clean 0-CVE scan. |
| `packages/core/integrations/cyclonedx/parser.py` | Parses CycloneDX 1.4/1.5/1.6 JSON, resolves `direct` vs. `transitive` vs. `unknown` dependency scope, and assigns SBOM completeness (`complete`, `incomplete`, `failed`). |
| `packages/core/engines/discovery/normalizer.py` | Parses Package URLs (PURLs), maps ecosystems, normalizes severities and multi-vendor CVSS metrics, deduplicates vulnerabilities, and correlates findings back to canonical `PackageRecord` IDs without duplicating package metadata. |
| `packages/core/engines/discovery/orchestrator.py` | Coordinates the full workflow, isolates SBOM vs. vulnerability failures to preserve partial evidence (`PARTIAL`), and guarantees errors are distinguishable from clean scans. |
| `packages/core/storage/evidence_store.py` | File-backed persistence creating per-assessment directories with raw artifacts, normalized assessment JSON, and SHA-256 `provenance.json`. |
| `packages/core/models/discovery.py` | Strict canonical Pydantic domain models (`AssessmentTarget`, `ScanMetadata`, `PackageRecord`, `VulnerabilityRecord`, `SBOMRecord`, `DiscoveryResult`). |

---

## 3. Prerequisites & Installation

### Python Package Setup
```powershell
# Create and activate virtual environment (Windows PowerShell)
python -m venv --system-site-packages .venv
.\.venv\Scripts\Activate.ps1
pip install --no-build-isolation -e ".[dev]"
```

### Trivy Prerequisite
The Discovery Engine requires the **Trivy CLI** binary (`>= 0.50.0` recommended).

- **Windows (Chocolatey / Winget):**
  ```powershell
  choco install trivy
  # or
  winget install AquaSecurity.Trivy
  ```
- **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt-get install trivy
  ```
- **macOS (Homebrew):**
  ```bash
  brew install trivy
  ```
- **Custom Path:** Set `VEXREACH_TRIVY_PATH=/path/to/trivy` in your environment or `.env`.

Verify availability via:
```powershell
vexreach check-config
```

---

## 4. CLI Usage & Options

```powershell
vexreach scan <TARGET_PATH> [OPTIONS]
```

| Option | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--output` | `-o` | `.vexreach/assessments/<assessment_id>` | Output directory for raw evidence and normalized reports. |
| `--format` | `-f` | `table` | Terminal output format (`table`, `text`, or `json`). |
| `--timeout` | `-t` | `300` | Subprocess timeout in seconds (`1` to `3600`). |
| `--verbose` | `-v` | `False` | Enable debug logging (sent to `stderr` when `--format json` is active). |

### Exit Codes
- `0`: Assessment `COMPLETED` cleanly (vulnerabilities may still be present; check assessment output).
- `1`: Assessment `FAILED` (invalid target, Trivy missing, both SBOM and vulnerability scan failed).
- `2`: Assessment `PARTIAL` (one stage succeeded and preserved partial evidence while the other failed).

---

## 5. Output Artifacts & Data Models

Every scan directory contains up to four persisted artifacts:
1. `sbom-cyclonedx.json` — Raw CycloneDX JSON emitted by Trivy.
2. `raw-trivy-vuln.json` — Raw Trivy vulnerability scan JSON.
3. `discovery-assessment.json` — Canonical `DiscoveryResult` JSON.
4. `provenance.json` — Assessment metadata, timestamps, scanner version, and SHA-256 digests of all preserved files.

### Canonical Models (`packages/core/models/discovery.py`)
- **`AssessmentTarget`**: `target_id`, `target_path`, `target_type`, `created_at`, `detected_ecosystems`, `detected_manifests`.
- **`ScanMetadata`**: `scanner_name`, `scanner_version`, `scan_started_at`, `scan_completed_at`, `scan_status` (`completed`/`partial`/`failed`), `errors`, `warnings`, `evidence_hashes`.
- **`PackageRecord`**: `package_id`, `name`, `version`, `ecosystem`, `purl`, `dependency_scope` (`direct`/`transitive`/`unknown`), `source_metadata`.
- **`VulnerabilityRecord`**: `vulnerability_id`, `package_id`, `installed_version`, `fixed_version`, `severity`, `cvss`, `description`, `references`, `primary_url`, `source`, `detection_timestamp`.
- **`SBOMRecord`**: `sbom_id`, `format`, `format_version`, `document_path`, `packages` (`list[package_id]`), `generation_timestamp`, `completeness_status` (`complete`/`incomplete`/`failed`), `document_sha256`.
- **`DiscoveryResult`**: `assessment_id`, `target`, `scan_metadata`, `sbom`, `packages`, `vulnerabilities`, `warnings`, `errors`.

To avoid duplicating package metadata, `DiscoveryResult.packages` stores each unique `PackageRecord` once, while `SBOMRecord.packages` and `VulnerabilityRecord.package_id` reference `PackageRecord.package_id`.

---

## 6. Storage Decision: File-Backed Store vs. SQLite

For Phase 3, VEXReach intentionally uses a file-backed `EvidenceStore` rather than SQLite:
- Raw Trivy JSON and CycloneDX SBOMs are large structured documents best preserved verbatim as immutable artifacts for cryptographic SHA-256 verification.
- Single-run CLI assessments require zero database migrations and inspect easily with standard JSON tools.
- Relational SQLite indexing (linking historical assessments, CVE drift, and OpenVEX statements across runs) will be layered on top of this evidence store in Phase 4/7.

---

## 7. Error Handling & Security Safeguards

- **No Code Execution**: Target inspection matches filenames only; Python `import`, `eval`, or `setup.py` execution is strictly prohibited.
- **No Shell Interpolation**: `TrivyClient` invokes `subprocess.run(..., shell=False)` with canonicalized absolute target paths (blocking `-flag` argument injection).
- **No Secret Leakage**: Trivy is invoked with `--scanners vuln` so repository secrets are never pulled into vulnerability JSON artifacts.
- **Bounded Memory & Time**: Output files exceeding `VEXREACH_MAX_SCANNER_OUTPUT_BYTES` (default 50 MB) and processes exceeding `--timeout` are terminated/rejected cleanly.
- **Fail-Closed Validation**: Unrelated JSON dicts, empty outputs, missing Trivy binaries, and partial failures are surfaced as `FAILED` or `PARTIAL`, never reported as `0 vulnerabilities / clean`.

---

## 8. Testing Strategy

- **Unit tests** (`tests/unit/`): `test_discovery_models.py`, `test_target_validator.py`, `test_trivy_client.py`, `test_trivy_parser.py`, `test_cyclonedx_parser.py`, `test_normalizer.py`, `test_evidence_store.py`.
- **Integration tests** (`tests/integration/test_discovery_pipeline.py`):
  - Fixture-driven / mocked `TrivyClient` end-to-end tests covering vulnerable, clean, partial-failure, timeout, invalid-target, malformed-JSON, and unavailable-Trivy scenarios, plus CLI `--format table` and `--format json`.
  - Live Trivy test marked `@pytest.mark.trivy`, which runs against `tests/fixtures/discovery/sample_app` when `trivy` is installed and explicitly skips otherwise.

---

## 9. Current Limitations

1. **Filesystem Scanning Only**: Container image scanning (`trivy image`) is deferred until filesystem workflows are battle-tested in production CI.
2. **External Advisory Feeds**: OSV, NVD, EPSS, and CISA KEV live enrichment are scheduled for Phase 4.
3. **Dual `VulnerabilityRecord` Models**: Phase 2's early advisory model in `packages/core/models/vulnerability.py` coexists with `packages/core/models/discovery.py` to avoid breaking Phase 2 tests; these will be consolidated when Phase 4 advisory enrichment is introduced.
4. **Trivy External Prerequisite**: Live scanning requires `trivy` to be installed on the host PATH or configured via `VEXREACH_TRIVY_PATH` (Docker fallback driver is not yet implemented).
