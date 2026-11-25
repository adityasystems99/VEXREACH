# VEXReach Backend Engineering Roadmap

VEXReach follows a **backend-first modular monolith** roadmap. User-facing frontend web applications (Next.js/React/Tailwind) are intentionally excluded from this repository and integrate strictly against the REST API v1 and OpenVEX 0.2.0 contracts.

## Completed Backend Foundations
- **Milestone 1–2:** Discovery Engine (Trivy filesystem SBOM/vulns, CycloneDX normalization, SHA-256 evidence store, SSRF/path safety).
- **Milestone 3–4:** Vulnerability Intelligence Engine (OSV.dev API v1 batch/advisory queries, SQLite cache, conservative SemVer/PEP 440 range evaluation, Python AST static reachability across Fixtures A–M).
- **Milestone 5:** AI Security Intelligence Engine (sandboxed/quarantined patch diff parser + interchangeable LLM providers: OpenAI, OpenRouter, Anthropic, Gemini, Ollama, Disabled/Heuristic) & Attack Path Intelligence Engine (entry-point exposure surfaces & AST taint tracing).
- **Milestone 6 (Python MVP & Go Static Reachability):**
  - Deterministic Policy Engine & OpenVEX 0.2.0 JSON-LD emitter + monotonic SQLite VEX revision history.
  - Cross-language static reachability contract (`contracts/analysis_contract.json`), pure-Go AST/call-graph worker (`packages/core/analysis/go_worker/`), Python subprocess bridge (`packages/core/analysis/go/`), Attack Path / Risk / OpenVEX integration, CLI `--language`, API `analyze_go`, Go benchmark harness (`6/6`), and tested Go Kubernetes Operator (`operators/vexreach-operator/`).
- **Backend Completion Expansion:**
  - Deterministic contextual Risk Intelligence (EPSS + CISA KEV + workload context + factor breakdowns).
  - Controlled Integration Registry (`IntegrationRegistry`, SSRF-safe HTTPS HMAC webhook sink).
  - Versioned FastAPI REST Backend (`/api/v1/*` with Bearer RBAC, rate limiting, payload size caps, SQLite audit logs, async assessment jobs, non-conflated vulnerability views, exported `openapi.v1.json`).
  - Runtime Trace Correlator (`RuntimeEvidenceCorrelator`), Continuous Drift Reassessment (`ContinuousEvidenceTracker`), and What-If Upgrade Simulator (`WhatIfSimulator`).
  - Multi-stage Python + Go Containerization (`Dockerfile`, `docker-compose.yml`), Namespace-Scoped Kubernetes manifests/CRD/Helm chart, Python & Go Reproducible Benchmark Suites, Self-Provenance / Security CI workflow, and Go CI workflow (`.github/workflows/go.yml`).

## Remaining Production / External Environment Milestones
1. **Go Inter-Procedural SSA Taint & Cluster Controller-Runtime Loop**: Static Go AST reachability & offline operator Job planner/status reconciler are compiled and verified; full Go SSA pointer/taint analysis (`golang.org/x/tools`) and live cluster controller-runtime API watch loops require controller-runtime dependencies & Kind/Kubernetes cluster access.
2. **Production Runtime Collectors (eBPF / OpenTelemetry Sidecars)**: Backend ingestion API (`/runtime-observations`) is live; kernel eBPF probes require Linux kernel/privileged runtime collector agents outside unit tests.
3. **Live Hosted Integrations Verification**: Live Trivy CLI scan execution, live OSV/KEV/EPSS remote API checks, and live LLM provider smoke tests require network/binary availability in CI or staging environments.
