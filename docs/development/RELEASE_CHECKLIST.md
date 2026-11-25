# VEXReach Release Readiness Checklist

**Target:** End-to-End Open-Source Production Backend Platform Release (Section 16 Acceptance Criteria + Backend-First Amendment)  
**Current Phase Status:** **Python & Go Backend Platform Complete (`163 passed, 3 skipped` pytest; `7` Go tests passed)**; live cluster controller API watch loops, `ruff`/`mypy`, and live Trivy/eBPF collector execution run in CI/cluster environments.

---

## Product Acceptance Criteria

- [x] Submit local repository filesystem target for dependency & vulnerability discovery (`vexreach scan` & `POST /api/v1/assessments`) *(Mocked Trivy verified; requires installed Trivy binary in live runs)*
- [ ] Submit container image target for scanning (`trivy image`) *(Planned after live Trivy image CLI integration)*
- [x] Generate and preserve CycloneDX SBOM + raw scanner evidence with SHA-256 provenance
- [x] Enrich findings conservatively from OSV.dev with SQLite cache and alias correlation
- [x] Correlate upstream advisories, patches, and diffs via quarantined AI Security Intelligence (`Milestone 3`) with multi-provider adapters (OpenAI, OpenRouter, Anthropic, Gemini, Ollama, Disabled/Heuristic)
- [x] Validate candidate vulnerable symbols with deterministic AST verification (`DependencySymbolResolver` + `CandidateSymbolValidator`)
- [x] Construct Python static call graph and evaluate bounded reachability (`Milestone 2`) + reproducible benchmark harness (`15/15`, `0` false-safe regressions)
- [x] Reconstruct conservative Attack Paths with input sources & trust/auth boundaries (`Milestone 4`)
- [x] Correlate structured runtime trace observations via `RuntimeEvidenceCorrelator` & `/runtime-observations` without treating misses as proof of safety *(Live Linux eBPF agent collectors external)*
- [x] Evaluate explainable contextual Risk Intelligence with EPSS / CISA KEV / CVSS (`Engine 5` + CLI `risk` + REST `/risk`)
- [x] Deterministically evaluate evidence policies, track statement versions, and emit schema-validated OpenVEX 0.2.0 documents (`Milestone 5`)
- [x] Support Go static call-graph analysis (`Milestone 6` — Go AST worker `go_worker`, Python bridge, CLI/API/Attack Path integration, and `6/6` Go benchmark verified)
- [x] Containerize isolated backend API & worker (`deploy/docker/`) and provide namespace-scoped Kubernetes CRD/RBAC/Job manifests & Helm chart (`deploy/kubernetes/`, `deploy/helm/vexreach/`)
- [x] Compile & test Go Kubernetes Operator planner and status reconciler (`operators/vexreach-operator/` verified via `go vet`/`go test`/`go build`; live cluster watch loop awaits Kind/Kubernetes cluster)
- [x] Support continuous drift reassessment & What-If upgrade simulator (`ContinuousEvidenceTracker`, `WhatIfSimulator`, `/reassess-plan`, `/simulate`)
- [x] Expose versioned FastAPI REST service (`apps/api`, exported `docs/api/openapi.v1.json`, RBAC/rate limits/audit logs) *(Frontend UI explicitly excluded per Amendment)*
- [x] Provide `.env.example`, credential guide, `LICENSE`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue/PR templates, `.github/workflows/security.yml` & `go.yml`, and release provenance generator (`scripts/generate_release_provenance.py`)
- [ ] Run full `ruff` / `mypy` / `pytest-cov` / live Trivy self-SBOM gates in GitHub Actions CI (`ci.yml`, `security.yml`) where all external binaries are installed
