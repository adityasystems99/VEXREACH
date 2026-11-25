# ADR-004: OSV Batch-First Enrichment, SQLite Cache, and Fail-Closed Version Evaluation

## Status
Accepted

## Context
Vulnerability scanners like Trivy report point-in-time findings with scalar fields (a single `FixedVersion` string, vendor-chosen severity, and limited advisory context). To determine practical impact accurately in downstream reachability and OpenVEX engines, VEXReach needs authoritative, multi-branch affected version ranges, alias graphs (`CVE`/`GHSA`/`PYSEC`/`GO`), and withdrawal signals.

Three design questions arose:
1. How to query OSV.dev efficiently without spamming one HTTP call per dependency on every scan.
2. Whether to introduce Redis or use SQLite for advisory caching.
3. How to evaluate version ranges across diverse ecosystems (`PyPI`, `npm`, `Go`, `Debian`, `Maven`, `Alpine`).

## Decision
1. **Batch-First OSV Querying + Alias Deduplication**:
   - Query `POST /v1/querybatch` for all discovered packages in bounded chunks (default 100), receiving lightweight `{id, modified}` stubs.
   - Fetch full advisory records via `GET /v1/vulns/{id}` only when missing from cache or when `modified` changed, and skip redundant `/v1/vulns/{CVE}` lookups when batch-fetched advisories already cover that CVE in `aliases`.
2. **Integrity-Checked Local SQLite Cache**:
   - Implement `SQLiteAdvisoryCache` using Python's built-in `sqlite3` against `settings.storage_path` (`.vexreach/vexreach.db`), verifying SHA-256 digests and enforcing TTL + upstream `modified` invalidation. Avoid Redis or external brokers.
3. **Strict Ecosystem-Specific Comparators with Kleene 3-Valued Fail-Closed Logic**:
   - Use PyPA `packaging.version.Version` (PEP 440) for `PyPI` and a strict SemVer 2.0.0 comparator for `SEMVER`, `Go`, `npm`, and `crates.io`.
   - For unsupported range schemes (`GIT`, `Debian`, `RPM`, `Alpine`, `Maven`) or invalid/missing versions, return `VersionMatchStatus.UNKNOWN` and aggregate multiple intervals using Kleene 3-valued logic (`AFFECTED > UNKNOWN > NOT_AFFECTED`).

## Consequences
### Positive
- Significantly reduces OSV HTTP round-trips and eliminates redundant 404 requests for aliased CVEs.
- Zero new infrastructure dependencies (no Redis/broker needed for local CLI or CI usage).
- Prevents false-negative safety claims from naive string comparison on complex distro version strings.

### Negative / Trade-offs
- OS package ecosystems (`Debian`, `Alpine`, `RPM`) report `UNKNOWN` version-range status until native version comparators are implemented.
- SQLite cache assumes single-host / local runner persistence (acceptable for modular monolith Phase 4).
