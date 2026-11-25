# VEXReach Attack Path Intelligence Engine (Milestone 4)

## Overview

The Attack Path Intelligence Engine (`packages/core/engines/attack_path/`) analyzes statically reachable Python call paths to model external exposure surfaces, input sources, conservative forward data-flow propagation, authentication/validation barriers, and explicit trust boundaries.

Static call-graph reachability does **not** imply attacker-controlled data reaches the vulnerable sink (`CALL_PATH_ONLY_TAINT_NOT_PROVEN` vs `TAINTED_FLOW_OBSERVED`).

## Components

- `surface_classifier.py` (`classify_entry_surface`): Classifies ingress exposure (`network_http_public`, `network_http_authenticated`, `cli_local_input`, `internal_function`, `unknown`), detects FastAPI `Depends(...)`/`Security(...)` and route auth decorators, and extracts HTTP/CLI/function parameters as candidate `InputSourceRecord`s.
- `taint_tracer.py` (`trace_taint_along_path`): Performs conservative intra-procedural AST assignment/call argument tracking across hops along each `ReachabilityPath`. Constant literals at sink calls preserve `call_path_only_taint_not_proven` instead of claiming taint. Explicit safe loaders/validation guards are captured as `BarrierEvidence`.
- `orchestrator.py` (`AttackPathOrchestrator`): Generates `AttackPathReport` attached to `DiscoveryResult.attack_paths` and persisted as `attack-paths.json` with SHA-256 provenance.

## CLI Usage

```bash
vexreach attack-paths ./out --target ./my-app
vexreach scan ./my-app --enrich --extract-symbols --analyze --attack-paths --output ./out
```
