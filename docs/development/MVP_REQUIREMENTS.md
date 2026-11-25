# VEXReach MVP Requirements & Acceptance Criteria

## 1. Objective of the MVP

The MVP delivers the minimal end-to-end, reproducible pipeline for analyzing a Python application repository:
1. Ingest application dependencies and known vulnerabilities (**Phase 3 Discovery Engine** + **Phase 4 OSV.dev Vulnerability Intelligence Engine** implemented; NVD/EPSS/KEV in later phases).
2. Construct an application static call graph from Python source code (**Phase 5 Python Static Reachability Engine** implemented).
3. Correlate candidate vulnerable dependency functions against application call paths (**Phase 5 Python Static Reachability Engine** implemented via validated `VulnerabilitySymbolManifest`).
4. Deterministically evaluate reachability (explicit 6-state static outcome implemented in Phase 5; runtime & full policy evaluation in later phases).
5. Emit an auditable, standards-compliant **OpenVEX 0.2.0** JSON document (planned).

See [DISCOVERY_ENGINE.md](DISCOVERY_ENGINE.md), [VULNERABILITY_INTELLIGENCE.md](VULNERABILITY_INTELLIGENCE.md), and [PYTHON_STATIC_REACHABILITY.md](PYTHON_STATIC_REACHABILITY.md) for acceptance criteria and boundaries.

---

## 2. Mandatory Test Corpus & Acceptance Criteria

The MVP is not complete until all six foundational acceptance tests pass deterministically:

### Test A: Reachable Function (Positive Case)
- **Scenario**: An application entry point (`main.py:handle_request`) invokes `helpers.py:process_data`, which in turn calls a candidate vulnerable function `insecure_lib.parser:parse_payload`.
- **Expected Outcome**:
  - Call graph traversal identifies the exact path: `["handle_request", "process_data", "insecure_lib.parser.parse_payload"]`.
  - Reachability status: `REACHABLE`.
  - OpenVEX status: `affected`.
  - Action statement: Upgrade or remediation recommended.

### Test B: Unreachable Function (Negative Case)
- **Scenario**: Application imports `insecure_lib.utils:safe_helper`, while the candidate vulnerable function is `insecure_lib.parser:parse_payload`. No call path connects the application to `parse_payload`.
- **Expected Outcome**:
  - Call graph traversal finds zero directed paths to `parse_payload`.
  - No unresolved dynamic dispatch exists.
  - Reachability status: `UNREACHABLE`.
  - OpenVEX status: `not_affected`.
  - Justification: `vulnerable_code_not_in_execute_path`.
  - Impact statement: Deterministic static path absence explanation.

### Test C: Dynamic Dispatch & Uncertainty (Edge Case)
- **Scenario**: Application resolves subroutines dynamically via `getattr(insecure_lib, dynamic_func_name)()` or `__import__()`.
- **Expected Outcome**:
  - Analysis flags unresolved dynamic dispatch.
  - Uncertainty is explicitly recorded (`DYNAMIC_DISPATCH_UNRESOLVED`).
  - Reachability status: `DYNAMIC_UNCERTAINTY`.
  - OpenVEX status: `under_investigation`.
  - System refuses to claim `not_affected`.

### Test D: Malformed / Adversarial SBOM
- **Scenario**: Ingested SBOM is corrupt, truncated, or contains schema-violating JSON.
- **Expected Outcome**:
  - Input validation fails cleanly with a structured `ValidationError`.
  - Pipeline exits gracefully with an explanatory message; no unhandled crash or traceback dump.

### Test E: Invalid / Hallucinated AI Output
- **Scenario**: Simulated LLM response returns non-existent module or malformed schema.
- **Expected Outcome**:
  - Pydantic schema validation rejects the payload.
  - Verification check against codebase AST fails.
  - Finding is marked as unverified; fallback to conservative `under_investigation`.

### Test F: OpenVEX 0.2.0 Schema Conformance
- **Scenario**: Generated OpenVEX document is validated against the official OpenVEX JSON-LD specification.
- **Expected Outcome**:
  - Required fields (`@context`, `@id`, `author`, `role`, `timestamp`, `version`, `statements`) are present and valid.
  - Status and justifications conform to OpenVEX enum values.

---

## 3. Engineering Quality Gates

1. **Python Compatibility**: Python 3.12+ (compatible with 3.14).
2. **Type Safety**: Full type annotations across all packages; strict Pydantic v2 schemas for all cross-module data boundaries.
3. **Structured Logging**: Unified `structlog` or standard library logging with JSON formatting support.
4. **Config Management**: Centralized `pydantic-settings` loaded from environment variables and config files.
5. **No Blind Shell Interpolation**: All external invocations must use parameterized arguments without shell injection hazards.
