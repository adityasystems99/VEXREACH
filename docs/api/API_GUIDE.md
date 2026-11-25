# VEXReach REST Backend API v1 Integration Guide

VEXReach is engineered strictly as a modular **backend vulnerability intelligence platform**. Any external web UI, CLI consumer, CI pipeline, or Kubernetes controller consumes VEXReach exclusively over this versioned REST API and machine-readable OpenVEX 0.2.0 / OpenAPI v1 contracts.

> **OpenAPI Specification:** Exported at [`openapi.v1.json`](./openapi.v1.json) and served live at `/api/v1/openapi.json` (interactive Swagger at `/api/v1/docs`, ReDoc at `/api/v1/redoc`).

---

## 1. Security Model & Governance

### Authentication & RBAC
When `VEXREACH_API_AUTH_ENABLED=true`, all `/api/v1/*` routes enforce `Authorization: Bearer <token>`. Keys are configured via `VEXREACH_API_KEYS` (`token:role` comma-separated entries):

| Role | Permitted Capabilities |
| :--- | :--- |
| `viewer` | Read assessments, findings, dependencies, reachability paths, attack paths, risk scores, evidence hashes, OpenVEX documents, history, and `/api/v1/integrations`. |
| `operator` | All `viewer` permissions plus creating assessments (`POST /api/v1/assessments`), ingesting runtime traces, running What-If remediation simulations, computing reassessment plans, and posting CI webhooks. |
| `admin` | All `operator` permissions plus inspecting SQLite security audit logs (`GET /api/v1/audit-logs`). Raw Bearer tokens are never logged — only redacted SHA-256 key prefixes (`key:<sha256[:12]>`). |

When `VEXREACH_API_AUTH_ENABLED=false` (local development default), requests run under local `admin` context without failing CI smoke tests, while **payload limits (`413`) and rate limits (`429`) remain active**.

### Request Governance & Error Envelope
- **Maximum request body bytes:** Configurable via `VEXREACH_API_MAX_REQUEST_BYTES` (default `5242880` = 5 MiB); oversized payloads receive HTTP `413` with `{"error_code": "PAYLOAD_TOO_LARGE", ...}`.
- **Rate limiting:** Sliding 60-second per-client window via `VEXREACH_API_RATE_LIMIT_PER_MINUTE` (default `120`); exceeded clients receive HTTP `429` with `Retry-After: 60` and `{"error_code": "RATE_LIMIT_EXCEEDED", ...}`.
- **Internal errors:** Unhandled server exceptions return sanitized JSON (`{"error_code": "INTERNAL_SERVER_ERROR", ...}`) with zero stack-trace leakage.
- **CORS:** Explicitly opt-in via `VEXREACH_API_CORS_ORIGINS` (`allow_credentials=False`).

---

## 2. Non-Conflated Vulnerability Response Contract

`GET /api/v1/assessments/{assessment_id}/vulnerabilities` returns `PaginatedVulnerabilitiesResponse` containing `VulnerabilityNonConflatedView` items. Consumers **MUST NEVER collapse** these independent dimensions into a single generic `"safe"` or `"exploitable"` boolean:

- `vulnerable_dependency_detected` (`bool`): Vulnerable package coordinate present in SBOM/scanner output.
- `candidate_symbol_identified` (`bool`) & `candidate_symbols` (`list[str]`): Extracted/mapped upstream vulnerable function(s).
- `static_path_identified` (`bool | null`): Bounded Python AST call-graph path from configured entry point (`null` when incomplete/unresolved or not analyzed).
- `reachability_state` (`string | null`): Explicit static state (`reachable`, `no_path_within_supported_subset`, `unresolved`, `analysis_incomplete`, etc.).
- `runtime_execution_observed` (`bool | null`): Confirmed runtime trace observation (`null` when unobserved — absence of runtime observation **never** proves unreachability).
- `analysis_incomplete` (`bool`) & `evidence_insufficient` (`bool`): Explicit uncertainty disclosure flags.
- `exploitability_established` (`bool`): Defaults strictly to `false` unless proven independently.
- `contextual_risk_score` (`float | null`) & `risk_priority_tier` (`P0_CRITICAL`..`P4_MITIGATED`): Deterministic remediation ranking (NOT exploitability proof).
- `openvex_status` (`affected`, `not_affected`, `fixed`, `under_investigation`) & `openvex_justification`: Conservative policy-engine verdict.

---

## 3. Core Endpoint Reference

### Health & Metadata
- `GET /healthz` — Liveness probe (`status`, `version`, `api_version: "v1"`).
- `GET /readyz` — Readiness probe verifying SQLite parent path & evidence artifact storage directory accessibility.
- `GET /api/v1/openapi.json` — OpenAPI v1 schema.

### Assessments & Asynchronous Jobs
- `POST /api/v1/assessments` (`operator`) — Launch discovery & configured analysis engines synchronously (`"async_execution": false`) or queued via background task (`"async_execution": true`), returning `JobStatusResponse` (`HTTP 202`).
- `GET /api/v1/jobs/{job_id}` (`viewer`) — Poll job state (`queued`, `running`, `completed`, `failed`) and obtain `assessment_id`.
- `GET /api/v1/assessments?limit=20&offset=0&scan_status=...` (`viewer`) — Paginated list of persisted assessments sorted newest-first.
- `GET /api/v1/assessments/{assessment_id}` (`viewer`) — Full canonical `DiscoveryResult` JSON.

### Findings & Engine Reports
- `GET /api/v1/assessments/{assessment_id}/vulnerabilities?severity=&reachability_state=&openvex_status=&limit=50&offset=0` (`viewer`) — Filterable, paginated non-conflated finding views.
- `GET /api/v1/assessments/{assessment_id}/dependencies?ecosystem=&scope=&limit=50&offset=0` (`viewer`) — Filterable normalized `PackageRecord` dependencies.
- `GET /api/v1/assessments/{assessment_id}/reachability` (`viewer`) — `StaticReachabilityReport`.
- `GET /api/v1/assessments/{assessment_id}/attack-paths` (`viewer`) — `AttackPathReport` (exposure surfaces & taint flow status).
- `GET /api/v1/assessments/{assessment_id}/risk` (`viewer`) — `RiskIntelligenceReport` (EPSS, CISA KEV, factor breakdowns).

### Evidence, OpenVEX, History, Runtime, Simulation & Continuous Reassessment
- `GET /api/v1/assessments/{assessment_id}/evidence` (`viewer`) — Artifact directory, SHA-256 evidence hashes, and provenance metadata.
- `GET /api/v1/assessments/{assessment_id}/openvex` (`viewer`) — Standards-compliant OpenVEX v0.2.0 JSON-LD document.
- `GET /api/v1/assessments/{assessment_id}/policy-evaluation` (`viewer`) — Policy completeness report & decision trace.
- `GET /api/v1/assessments/{assessment_id}/history` (`viewer`) — Monotonic SQLite OpenVEX revision history for the target.
- `POST /api/v1/assessments/{assessment_id}/runtime-observations` (`operator`) & `GET .../runtime-observations` (`viewer`) — Ingest confirmed symbol runtime traces and optionally re-score risk + OpenVEX.
- `POST /api/v1/assessments/{assessment_id}/simulate` (`operator`) — Run What-If dependency upgrade projections against OSV ranges (`validation_status: "pending_isolated_test_verification"`).
- `POST /api/v1/assessments/{assessment_id}/reassess-plan` (`operator`) — Compute selective engine re-execution plan upon source, SBOM, or advisory drift.
- `GET /api/v1/integrations` (`viewer`) — Inspect active integration adapters and least-privilege permission boundaries.
- `POST /api/v1/webhooks/ci` (`operator`) — Trigger drift analysis from CI push/PR/advisory events.
- `GET /api/v1/audit-logs?limit=100` (`admin`) — Retrieve immutable SQLite security audit trail.
