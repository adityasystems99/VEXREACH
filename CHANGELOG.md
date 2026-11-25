# Changelog

All notable backend engineering milestones for **VEXReach** are documented in this file.

## [0.1.0-dev] - Current Backend Platform Milestone (`feat/ai-security-intelligence`)

### Added
- **Go Static Reachability Engine & Complete Kubernetes Operator (`packages/core/analysis/go_worker/`, `packages/core/analysis/go/`, `operators/vexreach-operator/`)**:
  - Added cross-language contract [`contracts/analysis_contract.json`](contracts/analysis_contract.json) aligned with `StaticReachabilityReport`.
  - Built pure-Go AST static call-graph analyzer worker (`vexreach-go-analyze`) supporting `go.mod`, aliased/package imports, receiver methods, inline closures/goroutines, HTTP & Cobra entry points, conservative `reflect.*`/`plugin.Open`/dot-import/dynamic uncertainty flagging, depth caps, and dependency AST verification.
  - Built Python subprocess bridge `GoReachabilityAnalyzer` and multi-language orchestrator `run_hybrid_reachability_repository` / `run_hybrid_reachability_discovery`, wired into CLI (`vexreach analyze --language`, `vexreach scan --analyze`, `check-config`), REST API (`analyze_go`), `AttackPathOrchestrator`, `RiskIntelligenceOrchestrator`, `OpenVEXOrchestrator`, `IntegrationRegistry`, multi-stage `deploy/docker/Dockerfile`, `.github/workflows/go.yml`, Go benchmark harness (`benchmarks/run_go_benchmark.py` -> 6/6 exact matches), and `GO_STATIC_REACHABILITY.md`.
  - Completed `operators/vexreach-operator` (`BuildK8sBatchJobManifest`, `ReconcileAssessmentStatus`, `cmd/manager/main.go`, `go vet` & `go test` suite).
- **Versioned FastAPI REST Backend (`apps/api/`)**:
  - Health probes (`/healthz`, `/readyz`), versioned `/api/v1/openapi.json` (exported to `docs/api/openapi.v1.json`), Bearer RBAC (`viewer`, `operator`, `admin`), sliding-window rate limits (`429`), request body byte caps (`413`), CORS allowlist config, SQLite immutable audit log (`GET /api/v1/audit-logs`), persistent SQLite assessment job queue (`POST /api/v1/assessments`, `GET /api/v1/jobs/{id}`), non-conflated `/vulnerabilities` contract, and `/docs/api/API_GUIDE.md`.
- **Risk Intelligence Engine (`packages/core/engines/risk/`, `packages/core/integrations/threat_feeds/`)**:
  - Deterministic `[0..100]` remediation scoring (`P0_CRITICAL`..`P4_MITIGATED`) combining CVSS, FIRST EPSS, CISA KEV catalog flags, static reachability, attack-path exposure/taint status, runtime trace confirmation, and workload criticality — plus CLI `vexreach risk` and `vexreach scan --risk`.
- **Multi-Provider LLM & Controlled Integration Registry (`llm_provider.py`, `packages/core/integrations/registry.py`)**:
  - Added Google Gemini REST provider (`x-goog-api-key` header auth, zero query-string secrets), OpenRouter headers, shared `_post_with_retries` with `Retry-After` & backoff, `CredentialMissingError` validation, `register_llm_provider`, `IntegrationRegistry`, SSRF-safe `WebhookNotificationSink`, `.env.example`, and `docs/development/CREDENTIALS_AND_PROVIDERS.md`.
- **Runtime, Continuous Reassessment & What-If Simulator Engines**:
  - `RuntimeEvidenceCorrelator`, `ContinuousEvidenceTracker`, and `WhatIfSimulator` exposed over both Python domain services and REST `/api/v1/assessments/{id}/...` endpoints.
- **Deployment & Open-Source Governance Assets**:
  - Non-root multi-stage `deploy/docker/Dockerfile` & `docker-compose.yml`, namespace-scoped Kubernetes CRD + RBAC + Job manifests (`deploy/kubernetes/`), Helm chart (`deploy/helm/vexreach/`), Go Operator starter schema & job planner (`operators/vexreach-operator/`, uncompiled locally pending Go SDK), offline K8s helper (`packages/core/integrations/kubernetes.py`), reproducible Python benchmark harness (`benchmarks/run_python_benchmark.py`), release SHA-256 provenance script (`scripts/generate_release_provenance.py`), `.github/workflows/security.yml`, `LICENSE`, `CODE_OF_CONDUCT.md`, `.github/ISSUE_TEMPLATE/`, and `.github/PULL_REQUEST_TEMPLATE.md`.

### Security & Architecture Foundations (Earlier Milestones on Branch)
- AI Security Intelligence Engine (upstream patch diff parser, SSRF host allowlist, quarantined LLM JSON parser, deterministic symbol validator).
- Attack Path Intelligence Engine (route/ingress classifier and AST taint propagation tracker).
- Evidence Correlation & OpenVEX v0.2.0 Engine (fail-closed policy engine ensuring missing evidence / unverified dependency symbols / runtime non-observation NEVER yield `not_affected`, plus SQLite monotonic VEX history).
