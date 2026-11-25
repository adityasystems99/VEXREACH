# VEXReach AI Security Intelligence Engine (Milestone 3)

## Overview

The AI Security Intelligence Engine (`packages/core/engines/ai_intelligence/`) identifies candidate vulnerable symbols from advisories and upstream patches using deterministic patch diff/AST analysis combined with strictly quarantined LLM extraction.

It adheres cleanly to **ADR-003** and **THREAT_MODEL.md**:
- Advisory descriptions, commit messages, and patches are treated strictly as **untrusted data**.
- Prompt-injection indicators are quarantined with per-request nonce XML delimiters and flagged via `PromptInjectionSignal`.
- LLM responses are schema-validated strictly (`parse_llm_json_safely`); any unauthorized security verdicts (`vex_status`, `not_affected`, `reachable`, `exploitable`, `safe`) are stripped and logged (`LLM_UNAUTHORIZED_VERDICT_IGNORED`).
- Candidate symbols are validated deterministically by `CandidateSymbolValidator` against package import roots and optional local dependency ASTs (`DependencySymbolResolver`). Unverified LLM symbols remain `ai_assisted_unverified` and never auto-promote to `verified`.

## Implemented Components

- `sanitizer.py` (`PromptSanitizer`): Strips ANSI/control characters, bounds prompt length, tags indirect prompt injections (`ignore_instructions`, `override_security_verdict`, `system_role_spoof`, `command_execution_lure`), and wraps inputs in nonce-scoped untrusted tags.
- `patch_fetcher.py` (`PatchFetcher`): Fetches `.diff`/`.patch` commits from local files or strictly allowlisted HTTPS hosts (`github.com`, `api.github.com`, `raw.githubusercontent.com`) with redirect validation, SSRF IP blocking, `patch_max_bytes` bounds, and SHA-256 digests.
- `patch_parser.py` (`parse_unified_diff`, `compare_python_ast_versions`, `extract_patch_record`): Parses unified diffs and compares pre/post-patch Python ASTs (or aligns hunk spans with local dependency ASTs) without executing target code.
- `llm_provider.py`: Provider abstraction (`LLMProvider`) supporting `DisabledLLMProvider` (default offline heuristic-only mode), `OpenAICompatibleLLMProvider` (OpenAI, Ollama, vLLM), and `AnthropicLLMProvider`, using `SecretStr` for keys and zero tool/shell access.
- `validator.py` (`CandidateSymbolValidator`): Validates syntax, enforces package import root consistency, checks local dependency AST existence, and cleanly records `RejectedSymbolCandidate` items for hallucinated/cross-package proposals.
- `orchestrator.py` (`AISecurityIntelligenceOrchestrator`): Produces `AIAdvisoryIntelligenceReport` + validated `VulnerabilitySymbolManifest` and integrates with `EvidenceStore` (`ai-intelligence.json`, `raw-patch-evidence.json`, `candidate-symbols.json`).

## CLI Usage

```bash
# Run on a stored assessment with local patch fixtures & dependency ASTs
vexreach extract-symbols ./out --patch-dir ./patches --dependency-source ./vendor_src

# Full Discovery -> OSV -> AI/Patch Symbols -> Python Static Reachability pipeline
vexreach scan ./my-app --enrich --extract-symbols --patch-dir ./patches --analyze --output ./out
```
