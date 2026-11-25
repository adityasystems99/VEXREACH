# ADR-006: Fail-Closed OpenVEX 0.2.0 Policy & Static Taint Separation

- **Status:** Accepted
- **Date:** 2026-11-25
- **Milestones:** 4 (Attack Path Intelligence) & 5 (Evidence and OpenVEX)

## Context

Completing the end-to-end Python MVP requires translating multi-engine evidence (Discovery, OSV Intelligence, AI/Patch Symbols, Python Static Reachability, Attack Paths) into standardized OpenVEX 0.2.0 statements while preventing false-negative security clearances (`not_affected`) and alert conflation.

## Decision

1. **Strict Separation of Call Reachability vs. Taint Flow vs. OpenVEX Verdict:**
   - Static call-graph reachability (`REACHABLE`) is preserved independently from conservative forward taint propagation (`tainted_flow_observed` vs `call_path_only_taint_not_proven` vs `sanitized_or_validated`).
   - Attack paths never overwrite reachability or directly emit OpenVEX verdicts without deterministic policy checks.

2. **Fail-Closed `not_affected` Completeness Gate:**
   - Emitting `not_affected` (`vulnerable_code_not_in_execute_path`) requires `ScanStatus.COMPLETED`, `SBOMCompletenessStatus.COMPLETE`, conflict-free OSV intelligence, untruncated static reachability with active entry points and zero unresolved dynamic calls, `NO_PATH_WITHIN_SUPPORTED_SUBSET` for every candidate symbol, AND deterministic AST verification confirming the candidate symbol exists in supplied dependency source (`VERIFIED_IN_DEPENDENCY_SOURCE`).
   - Any gap defaults cleanly to `under_investigation`.

3. **Schema Invariants & Revision History:**
   - `VEXStatement` enforces OpenVEX 0.2.0 invariants directly at the Pydantic validation boundary (`not_affected` requires `justification` or `impact_statement`; `justification` is forbidden on other statuses).
   - `SQLiteVEXStore` tracks monotonic OpenVEX document versions (`v1`, `v2`, ...) with SHA-256 hashes per target inside `.vexreach/vexreach.db`.

## Consequences

- **Positive:** Eliminates silent false negatives from missing dependency ASTs, unresolved dynamic Python constructs, partial SBOMs, or scanner-vs-advisory disagreements, and ensures every emitted `.vex.json` passes OpenVEX 0.2.0 structural checks.
- **Negative / Trade-offs:** Scans without `--dependency-source` emit `under_investigation` rather than `not_affected` even when static code shows no path, requiring teams to supply source trees/wheels for strict `not_affected` assertions.
