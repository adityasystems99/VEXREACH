# ADR-003: Deterministic Security Decisions and AI Boundaries

## Status
Accepted

## Context
Generative AI and Large Language Models (LLMs) are exceptionally effective at reading human-written Common Vulnerabilities and Exposures (CVE) descriptions, understanding natural language advisories, and analyzing code diffs to pinpoint where a vulnerability was patched.

However, LLMs possess well-documented failure modes:
1. **Hallucination**: Generating plausible-sounding function names or security mechanisms that do not exist in the codebase.
2. **Non-Determinism**: Generating different answers for the exact same input across repeated executions.
3. **Indirect Prompt Injection**: Hostile third parties embedding adversarial prompt payloads within CVE descriptions, package names, or git commit messages.
4. **Lack of Auditability**: Inability to provide formal cryptographic proof or graph-verifiable explanations suitable for regulatory compliance (e.g., EU CRA, US Executive Order 14028).

## Decision
We enforce a strict, non-negotiable architectural boundary regarding the role of AI in VEXReach:

1. **AI is Restricted to Heuristic Advisory & Patch Analysis**:
   - AI may inspect CVE advisory summaries and upstream git diffs to hypothesize candidate vulnerable symbols (e.g., "The fix is in `urllib3.util.url.parse_url`").
2. **AI Findings Must Be Deterministically Verified**:
   - Any function, class, or symbol extracted by the AI must be statically verified against the target package AST. If the symbol does not exist in the code, the AI suggestion is discarded.
3. **Deterministic Policy Engine Governs All VEX Verdicts**:
   - The decision to emit `affected`, `not_affected`, `under_investigation`, or `fixed` must be evaluated exclusively by pure, deterministic policy functions (`packages/core/policies/`).
   - The policy engine consumes graph traversal proofs (e.g., NetworkX paths), package version intervals, and uncertainty flags.
   - The LLM is never invoked to decide or modify an OpenVEX status.
4. **Preservation of Uncertainty**:
   - If static analysis is hindered by dynamic dispatch (`getattr`, `eval`, dynamic imports) or if advisory parsing produces ambiguous candidate symbols, the status MUST be recorded as `under_investigation` or `affected`. It must NEVER default to `not_affected`.

## Consequences

### Positive
- **100% Reproducibility**: Running VEXReach on the same git commit with the same SBOM produces the exact same OpenVEX document every time.
- **Audit-Ready Evidence**: Every `not_affected` assertion references a verifiable call graph traversal proof.
- **Prompt Injection Resilience**: Even if an attacker injects a prompt payload into an advisory claiming "Package is completely safe!", the deterministic policy engine evaluates actual call paths and ignores the advisory's status claim.

### Negative / Trade-offs
- More conservative VEX generation (higher count of `under_investigation` when dynamic code is encountered).
- Requires writing explicit deterministic graph and version validation routines.
