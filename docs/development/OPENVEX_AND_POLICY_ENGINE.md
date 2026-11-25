# VEXReach Evidence & OpenVEX 0.2.0 Engine (Milestone 5)

## Overview

The Evidence & OpenVEX Engine combines deterministic completeness gating (`packages/core/policies/vex_policy.py`), OpenVEX 0.2.0 schema validation (`packages/core/engines/openvex/validator.py`), SQLite document revision history (`packages/core/storage/vex_history.py`), and `OpenVEXOrchestrator` to emit verifiable OpenVEX 0.2.0 JSON-LD statements (`openvex.vex.json`) and policy audit reports (`policy-evaluation.json`).

## Fail-Closed Policy Rules

VEXReach strictly obeys the following deterministic rules:
1. **`affected` (`RULE_01_STATIC_REACHABLE_PATH`, `RULE_03_RUNTIME_OBSERVATION`)**: Emitted when any candidate symbol has a static `REACHABLE` path or confirmed runtime execution observation, including attack surface and upgrade recommendations (`action_statement`).
2. **`under_investigation` (`RULE_02`, `RULE_04`, `RULE_06`)**: Enforced whenever Trivy and OSV advisories conflict, static reachability produced no result, candidate symbols are missing/unverified in dependency source AST (`dependency_source_unavailable` / `not_found_in_dependency_source`), dynamic calls remain unresolved, analysis was truncated/incomplete, or SBOM/scan completeness failed.
3. **`not_affected` (`RULE_05_VERIFIED_NOT_IN_EXECUTE_PATH`)**: Emitted ONLY when **all** completeness conditions hold simultaneously:
   - Scan `completed` and SBOM `complete`
   - No intelligence conflict or failure
   - Zero parse failures, zero graph truncation, active entry points present
   - All candidate symbols state `no_path_within_supported_subset` with zero unresolved calls
   - All candidate symbols verified present in local dependency source AST (`verified_in_dependency_source`)

Runtime non-observation alone never triggers `not_affected`.

## CLI Usage

```bash
# Emit and validate OpenVEX 0.2.0 JSON for a persisted assessment
vexreach vex ./out --format json > openvex.vex.json

# View monotonic revision history recorded in SQLite
vexreach vex ./out --history

# Full end-to-end Python MVP pipeline
vexreach scan ./my-app --enrich --extract-symbols --patch-dir ./patches --dependency-source ./vendor --analyze --attack-paths --emit-vex --output ./out
```
