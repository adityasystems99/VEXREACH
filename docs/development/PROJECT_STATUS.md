# VEXReach Project Status

**Last Updated:** 2026-11-25  
**Current Branch:** `feat/ai-security-intelligence` (branched from `master` @ `9c2f2b7`; uncommitted changes preserved for human review)  
**Verified Backend Suites:**
- **Python (`pytest -v -rs`):** `163 passed, 3 skipped in 44.34s`
- **Go (`go test -v ./...`):** `3 passed` (`go_worker/internal/analyzer`) + `4 passed` (`vexreach-operator/api/v1alpha1` & `internal/controller`)
**Product Delivery Scope:** Backend-Only Vulnerability Intelligence Platform (Python + Go CLI/REST API v1 + OpenVEX + K8s Operator/Docker; frontend UI excluded per Amendment)

---

## 1. Host Environment & Toolchain Audit

| Tool / Runtime | Status | Notes |
| --- | --- | --- |
| Python (`.venv`) | Available (`3.14.0`) | Hosts `fastapi`, `uvicorn`, `pydantic`, `typer`, `rich`, `networkx`, `httpx`, `packaging`, `pyyaml`, `pytest` |
| Go Toolchain | Available (`go1.27.4 windows/amd64`) | Installed at `C:\Program Files\Go\bin\go.exe`; compiles & tests `go_worker` and `vexreach-operator` |
| Docker Desktop CLI | Available | Installed at `C:\Program Files\Docker\Docker\resources\bin\docker.exe` |
| `kubectl` | Available | Installed at `C:\Program Files\Docker\Docker\resources\bin\kubectl.exe` |
| `trivy` CLI | Unavailable locally | Trivy unit/integration suite verified via mocked fixtures; live scan skipped |
| `ruff` / `mypy` / `pytest-cov` / `helm` | Unavailable locally | Configured in `pyproject.toml` and CI workflows (`.github/workflows/ci.yml`, `go.yml`, `security.yml`) |

---

## 2. Capability Status Matrix

Statuses follow taxonomy: `NOT_STARTED`, `IN_PROGRESS`, `IMPLEMENTED_UNVERIFIED`, `IMPLEMENTED_TESTED`, `BLOCKED`, `NEEDS_REFACTORING`.

| Milestone / Engine | Capability | Status | Evidence / Tests |
| --- | --- | --- | --- |
| M1 — Foundation | Project config, Pydantic base, safe paths, logging, CLI | `IMPLEMENTED_TESTED` | `test_config.py`, `test_safe_path.py`, `test_logging.py`, `test_models.py`, `test_cli.py` |
| Backend REST API (`apps/api/`) | FastAPI REST v1, Bearer RBAC, rate limits, body caps, SQLite jobs, audit logs, non-conflated schemas, `openapi.v1.json` | `IMPLEMENTED_TESTED` | `tests/integration/test_api_backend.py`, `docs/api/openapi.v1.json`, `docs/api/API_GUIDE.md` |
| Engine 1 — Discovery | Local filesystem Trivy scan + CycloneDX 1.4–1.6 + PURL normalization | `IMPLEMENTED_TESTED` | `test_target_validator.py`, `test_trivy_*`, `test_cyclonedx_parser.py`, `test_normalizer.py`, `test_discovery_pipeline.py` (1 live Trivy skip) |
| Engine 1B — Intelligence | OSV.dev `/querybatch` + `/vulns/{id}`, SQLite SHA-256 cache, alias correlation, PEP 440 / SemVer range checks | `IMPLEMENTED_TESTED` | `test_osv_*`, `test_correlator.py`, `test_advisory_cache.py`, `test_version_ranges.py`, `test_intelligence_pipeline.py` (1 offline OSV skip) |
| M2 — Python Static Reachability | Standard-library `ast` parsing, imports, symbols, calls, entry points, bounded `networkx.DiGraph`, dependency AST verification, CLI `analyze`, benchmark harness | `IMPLEMENTED_TESTED` | `test_reachability_models.py`, `test_python_*`, `test_python_reachability.py`, `benchmarks/run_python_benchmark.py` (15/15) |
| M3 — AI Security Intelligence & Providers | Patch diff parser, nonce sanitizer, multi-LLM (OpenAI, OpenRouter, Anthropic, Gemini, Ollama, Disabled/Heuristic), retries, validator, `IntegrationRegistry` | `IMPLEMENTED_TESTED` | `test_ai_sanitizer_and_llm.py`, `test_patch_parser_and_validator.py`, `test_ai_security_pipeline.py`, `test_providers_and_registry.py` |
| M4 — Attack Path Intelligence | Surface & auth/Depends barrier classifier, conservative inter-procedural AST taint propagation, CLI `attack-paths` | `IMPLEMENTED_TESTED` | `test_attack_path.py`, `test_attack_path_pipeline.py` |
| Engine 5 — Risk Intelligence | Deterministic `[0..100]` prioritization (`P0`–`P4`), EPSS/KEV snapshot client, workload context, CLI `risk` & `scan --risk` | `IMPLEMENTED_TESTED` | `tests/unit/test_risk_intelligence.py`, `test_api_backend.py` |
| M5 — Evidence & OpenVEX | Fail-closed policy engine, OpenVEX 0.2.0 invariant & JSON-LD schema validator, SQLite monotonic history (`SQLiteVEXStore`), CLI `vex` | `IMPLEMENTED_TESTED` | `test_openvex_policy_and_validator.py`, `test_openvex_mvp_pipeline.py` |
| M10–M12 — Runtime, Continuous, What-If | `RuntimeEvidenceCorrelator`, `ContinuousEvidenceTracker`, `WhatIfSimulator` + API endpoints (`/runtime-observations`, `/reassess-plan`, `/simulate`, `/webhooks/ci`) | `IMPLEMENTED_TESTED` | `tests/unit/test_runtime_continuous_simulator.py`, `tests/integration/test_api_backend.py` |
| M7–M9 — Containers, K8s & Operator | Multi-stage Python+Go `Dockerfile`, `docker-compose.yml`, namespace-scoped CRD/RBAC/Job YAML (`deploy/kubernetes/`), Helm chart, offline K8s helper (`kubernetes.py`), compiled & tested Go Operator (`operators/vexreach-operator/`) | `IMPLEMENTED_TESTED` | `test_deployment_and_k8s.py`, `go vet` & `go test` (`1 + 3` passed) |
| M6 — Go Static Analysis | Cross-language `contracts/analysis_contract.json`, pure-Go AST/call-graph worker (`go_worker`), Python bridge (`GoReachabilityAnalyzer`), hybrid CLI `--language`/API `analyze_go`, Attack Path/Risk/OpenVEX wiring, benchmark suite (`6/6`) | `IMPLEMENTED_TESTED` | `test_go_reachability_pipeline.py`, `test_benchmark_runner.py`, `go test` (`3` passed) |
| Frontend Web UI | Next.js / React / Tailwind web interfaces | *Excluded* | Explicitly excluded by Backend-First Product Completion Amendment; backend API/OpenAPI contracts provided cleanly |

---

## 3. Remaining External-Environment Verification

1. **Cluster / Container / Live Scanner Execution**: Live Kind/Kubernetes API control-plane reconciliation loop (`controller-runtime`), privileged Linux eBPF runtime collectors, live Trivy scans, and `ruff`/`mypy` CI gates execute in container/Kubernetes/GitHub Actions runners.
