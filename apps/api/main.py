"""Versioned FastAPI REST backend exposing VEXReach discovery, analysis, and OpenVEX APIs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from apps.api.schemas import (
    AssessmentCreateRequest,
    AuditLogEntryResponse,
    EvidenceArtifactsResponse,
    HealthResponse,
    JobStatusResponse,
    PaginatedAssessmentsResponse,
    PaginatedDependenciesResponse,
    PaginatedVulnerabilitiesResponse,
    ReadinessResponse,
    ReassessmentPlanRequest,
    RuntimeObservationsIngestRequest,
    SimulationRequest,
    WebhookCIRequest,
    WebhookCIResponse,
)
from apps.api.security import (
    AuditLogger,
    AuthPrincipal,
    RequestGovernanceMiddleware,
    require_role,
)
from apps.api.services import (
    SQLiteJobStore,
    build_assessment_summary,
    build_non_conflated_vulnerabilities,
    execute_assessment_pipeline_job,
    list_persisted_assessments,
)
from packages.core import __version__
from packages.core.config.settings import Settings, get_settings
from packages.core.engines.continuous import ContinuousEvidenceTracker
from packages.core.engines.openvex import OpenVEXOrchestrator
from packages.core.engines.risk import RiskIntelligenceOrchestrator
from packages.core.engines.runtime import RuntimeEvidenceCorrelator
from packages.core.engines.simulator import WhatIfSimulator
from packages.core.integrations.registry import IntegrationDescriptor, IntegrationRegistry
from packages.core.models.attack_path import AttackPathReport
from packages.core.models.extensions import (
    ContinuousReassessmentPlan,
    RuntimeEvidenceReport,
    RuntimeObservationRecord,
    WhatIfSimulationReport,
)
from packages.core.models.openvex import OpenVEXPolicyReport
from packages.core.models.reachability import StaticReachabilityReport
from packages.core.models.risk import RiskIntelligenceReport
from packages.core.storage.evidence_store import EvidenceStore
from packages.core.storage.vex_history import SQLiteVEXStore


def create_app(
    settings: Settings | None = None,
    *,
    trivy_client_factory: Any = None,
) -> FastAPI:
    """Create configured FastAPI backend application instance (without frontend coupling)."""
    cfg = settings or get_settings()
    app = FastAPI(
        title="VEXReach Backend API",
        version=__version__,
        description=(
            "Backend Vulnerability Intelligence API distinguishing vulnerable dependency "
            "presence, candidate symbols, static call paths, runtime observations, and OpenVEX policy."
        ),
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
    )

    app.state.settings = cfg
    app.state.evidence_store = EvidenceStore(cfg.default_output_dir)
    app.state.job_store = SQLiteJobStore(cfg.storage_path)
    app.state.vex_history_store = SQLiteVEXStore(cfg.storage_path)
    app.state.audit_logger = AuditLogger(cfg.storage_path)
    app.state.integration_registry = IntegrationRegistry()
    app.state.trivy_client_factory = trivy_client_factory

    app.add_middleware(
        RequestGovernanceMiddleware,
        max_request_bytes=cfg.api_max_request_bytes,
        rate_limit_per_minute=cfg.api_rate_limit_per_minute,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(Exception)
    async def _safe_internal_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error_code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected backend error occurred; inspect server logs for details.",
            },
        )

    def _load_or_404(request: Request, assessment_id: str):
        store: EvidenceStore = request.app.state.evidence_store
        try:
            return store.load_assessment(assessment_id)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/healthz", response_model=HealthResponse, tags=["System"])
    def healthz() -> HealthResponse:
        return HealthResponse(version=__version__)

    @app.get("/readyz", response_model=ReadinessResponse, tags=["System"])
    def readyz(request: Request) -> ReadinessResponse:
        cur_settings: Settings = request.app.state.settings
        db_ok = True
        try:
            cur_settings.storage_path.parent.mkdir(parents=True, exist_ok=True)
            cur_settings.default_output_dir.mkdir(parents=True, exist_ok=True)
            out_ok = cur_settings.default_output_dir.is_dir()
        except OSError:
            db_ok = False
            out_ok = False
        ready = db_ok and out_ok
        return ReadinessResponse(
            status="ready" if ready else "degraded",
            storage_writable=db_ok,
            output_dir_accessible=out_ok,
            checks={"sqlite_storage": db_ok, "evidence_dir": out_ok},
        )

    @app.post(
        "/api/v1/assessments",
        response_model=JobStatusResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["Assessments"],
    )
    def create_assessment(
        payload: AssessmentCreateRequest,
        background_tasks: BackgroundTasks,
        request: Request,
        principal: AuthPrincipal = Depends(require_role("operator")),
    ) -> JobStatusResponse:
        target = Path(payload.target_path)
        if not target.exists() or target.is_symlink():
            raise HTTPException(
                status_code=400,
                detail="Target path must exist and must not be a symlink.",
            )
        job_store: SQLiteJobStore = request.app.state.job_store
        ev_store: EvidenceStore = request.app.state.evidence_store
        cur_settings: Settings = request.app.state.settings
        factory = request.app.state.trivy_client_factory
        trivy_client = factory() if callable(factory) else None

        job = job_store.create_job(str(target))
        request.app.state.audit_logger.log(
            principal=principal,
            action="create_assessment",
            resource=f"job:{job.job_id}",
            status_code=202 if payload.async_execution else 200,
            detail=f"target={target}",
        )
        if payload.async_execution:
            background_tasks.add_task(
                execute_assessment_pipeline_job,
                job_id=job.job_id,
                request=payload,
                settings=cur_settings,
                job_store=job_store,
                evidence_store=ev_store,
                trivy_client=trivy_client,
            )
            return job

        execute_assessment_pipeline_job(
            job_id=job.job_id,
            request=payload,
            settings=cur_settings,
            job_store=job_store,
            evidence_store=ev_store,
            trivy_client=trivy_client,
        )
        completed = job_store.get_job(job.job_id)
        assert completed is not None
        return completed

    @app.get("/api/v1/jobs/{job_id}", response_model=JobStatusResponse, tags=["Assessments"])
    def get_job_status(
        job_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> JobStatusResponse:
        job = request.app.state.job_store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
        return job

    @app.get(
        "/api/v1/assessments",
        response_model=PaginatedAssessmentsResponse,
        tags=["Assessments"],
    )
    def list_assessments(
        request: Request,
        limit: int = Query(default=20, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        scan_status: str | None = Query(default=None),
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> PaginatedAssessmentsResponse:
        rows = list_persisted_assessments(request.app.state.evidence_store)
        if scan_status:
            rows = [
                (r, p) for r, p in rows if r.scan_metadata.scan_status.value == scan_status.lower()
            ]
        total = len(rows)
        sliced = rows[offset : offset + limit]
        return PaginatedAssessmentsResponse(
            total=total,
            limit=limit,
            offset=offset,
            items=[build_assessment_summary(res) for res, _ in sliced],
        )

    @app.get(
        "/api/v1/assessments/{assessment_id}",
        tags=["Assessments"],
    )
    def get_assessment(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        res, _ = _load_or_404(request, assessment_id)
        return res.model_dump(mode="json")

    @app.get(
        "/api/v1/assessments/{assessment_id}/vulnerabilities",
        response_model=PaginatedVulnerabilitiesResponse,
        tags=["Findings"],
    )
    def get_vulnerabilities(
        assessment_id: str,
        request: Request,
        severity: str | None = Query(default=None),
        reachability_state: str | None = Query(default=None),
        openvex_status: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> PaginatedVulnerabilitiesResponse:
        res, _ = _load_or_404(request, assessment_id)
        views = build_non_conflated_vulnerabilities(res)
        if severity:
            views = [v for v in views if v.severity.upper() == severity.strip().upper()]
        if reachability_state:
            views = [v for v in views if v.reachability_state == reachability_state.strip().lower()]
        if openvex_status:
            views = [v for v in views if v.openvex_status == openvex_status.strip().lower()]
        total = len(views)
        return PaginatedVulnerabilitiesResponse(
            assessment_id=res.assessment_id,
            total=total,
            limit=limit,
            offset=offset,
            items=views[offset : offset + limit],
        )

    @app.get(
        "/api/v1/assessments/{assessment_id}/dependencies",
        response_model=PaginatedDependenciesResponse,
        tags=["Findings"],
    )
    def get_dependencies(
        assessment_id: str,
        request: Request,
        ecosystem: str | None = Query(default=None),
        scope: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> PaginatedDependenciesResponse:
        res, _ = _load_or_404(request, assessment_id)
        pkgs = list(res.packages)
        if ecosystem:
            pkgs = [p for p in pkgs if p.ecosystem.lower() == ecosystem.strip().lower()]
        if scope:
            pkgs = [p for p in pkgs if p.dependency_scope.value == scope.strip().lower()]
        total = len(pkgs)
        return PaginatedDependenciesResponse(
            assessment_id=res.assessment_id,
            total=total,
            limit=limit,
            offset=offset,
            items=pkgs[offset : offset + limit],
        )

    @app.get(
        "/api/v1/assessments/{assessment_id}/reachability",
        response_model=StaticReachabilityReport,
        tags=["Analysis"],
    )
    def get_reachability(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> StaticReachabilityReport:
        res, _ = _load_or_404(request, assessment_id)
        if res.reachability is None:
            raise HTTPException(
                status_code=404,
                detail="Static reachability analysis has not been run for this assessment.",
            )
        return res.reachability

    @app.get(
        "/api/v1/assessments/{assessment_id}/attack-paths",
        response_model=AttackPathReport,
        tags=["Analysis"],
    )
    def get_attack_paths(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> AttackPathReport:
        res, _ = _load_or_404(request, assessment_id)
        if res.attack_paths is None:
            raise HTTPException(
                status_code=404,
                detail="Attack Path Intelligence has not been run for this assessment.",
            )
        return res.attack_paths

    @app.get(
        "/api/v1/assessments/{assessment_id}/risk",
        response_model=RiskIntelligenceReport,
        tags=["Risk"],
    )
    def get_risk(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> RiskIntelligenceReport:
        res, _ = _load_or_404(request, assessment_id)
        if res.risk_assessment is None:
            raise HTTPException(
                status_code=404,
                detail="Risk Intelligence evaluation has not been run for this assessment.",
            )
        return res.risk_assessment

    @app.get(
        "/api/v1/assessments/{assessment_id}/runtime-observations",
        response_model=RuntimeEvidenceReport,
        tags=["Runtime"],
    )
    def get_runtime_observations(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> RuntimeEvidenceReport:
        res, _ = _load_or_404(request, assessment_id)
        if res.runtime_evidence is None:
            raise HTTPException(
                status_code=404,
                detail="No runtime observations ingested for this assessment yet.",
            )
        return res.runtime_evidence

    @app.post(
        "/api/v1/assessments/{assessment_id}/runtime-observations",
        response_model=RuntimeEvidenceReport,
        tags=["Runtime"],
    )
    def ingest_runtime_observations(
        assessment_id: str,
        payload: RuntimeObservationsIngestRequest,
        request: Request,
        principal: AuthPrincipal = Depends(require_role("operator")),
    ) -> RuntimeEvidenceReport:
        res, artifacts = _load_or_404(request, assessment_id)
        domain_observations = [
            RuntimeObservationRecord.model_validate(
                {k: v for k, v in obs.model_dump(mode="python").items() if v is not None},
                strict=False,
            )
            for obs in payload.observations
        ]
        res, rt_report, rt_map = RuntimeEvidenceCorrelator().ingest_observations(
            res,
            domain_observations,
            coverage_percent=payload.instrumentation_coverage_percent,
        )
        store: EvidenceStore = request.app.state.evidence_store
        if payload.re_evaluate_vex_and_risk:
            res, risk_report = RiskIntelligenceOrchestrator().evaluate(
                res, runtime_observations=rt_map
            )
            store.persist_risk_artifacts(artifacts, risk_report)
            res, _ = OpenVEXOrchestrator(
                settings=request.app.state.settings,
                vex_history_store=request.app.state.vex_history_store,
                evidence_store=store,
            ).generate(res, artifacts=artifacts, runtime_observations=rt_map)
        else:
            store.persist_assessment(artifacts=artifacts, result=res)

        request.app.state.audit_logger.log(
            principal=principal,
            action="ingest_runtime_observations",
            resource=f"assessment:{assessment_id}",
            status_code=200,
            detail=f"observations={len(payload.observations)}",
        )
        return rt_report

    @app.post(
        "/api/v1/assessments/{assessment_id}/simulate",
        response_model=WhatIfSimulationReport,
        tags=["Simulation"],
    )
    def simulate_remediation(
        assessment_id: str,
        payload: SimulationRequest,
        request: Request,
        principal: AuthPrincipal = Depends(require_role("operator")),
    ) -> WhatIfSimulationReport:
        res, _ = _load_or_404(request, assessment_id)
        sim_report = WhatIfSimulator().simulate_upgrades(res, payload.proposals)
        request.app.state.audit_logger.log(
            principal=principal,
            action="simulate_remediation",
            resource=f"assessment:{assessment_id}",
            status_code=200,
            detail=f"proposals={len(payload.proposals)}",
        )
        return sim_report

    @app.get(
        "/api/v1/assessments/{assessment_id}/evidence",
        response_model=EvidenceArtifactsResponse,
        tags=["Evidence & OpenVEX"],
    )
    def get_evidence(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> EvidenceArtifactsResponse:
        res, artifacts = _load_or_404(request, assessment_id)
        prov = None
        if artifacts.provenance_path.is_file():
            prov = json.loads(artifacts.provenance_path.read_text(encoding="utf-8"))
        return EvidenceArtifactsResponse(
            assessment_id=res.assessment_id,
            assessment_dir=str(artifacts.assessment_dir),
            evidence_hashes=dict(res.scan_metadata.evidence_hashes),
            provenance=prov,
        )

    @app.get(
        "/api/v1/assessments/{assessment_id}/openvex",
        tags=["Evidence & OpenVEX"],
    )
    def get_openvex_document(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        res, _ = _load_or_404(request, assessment_id)
        if res.policy_evaluation is None:
            raise HTTPException(
                status_code=404,
                detail="OpenVEX statement document has not been emitted for this assessment.",
            )
        return json.loads(res.policy_evaluation.openvex_document.to_openvex_json())

    @app.get(
        "/api/v1/assessments/{assessment_id}/policy-evaluation",
        response_model=OpenVEXPolicyReport,
        tags=["Evidence & OpenVEX"],
    )
    def get_policy_evaluation(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> OpenVEXPolicyReport:
        res, _ = _load_or_404(request, assessment_id)
        if res.policy_evaluation is None:
            raise HTTPException(status_code=404, detail="OpenVEX policy report unavailable.")
        return res.policy_evaluation

    @app.get(
        "/api/v1/assessments/{assessment_id}/history",
        tags=["Evidence & OpenVEX"],
    )
    def get_assessment_history(
        assessment_id: str,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        res, _ = _load_or_404(request, assessment_id)
        history_store: SQLiteVEXStore = request.app.state.vex_history_store
        revisions = history_store.list_history(res.target.target_path)
        return {
            "assessment_id": res.assessment_id,
            "target_path": res.target.target_path,
            "openvex_revisions": revisions,
        }

    @app.post(
        "/api/v1/assessments/{assessment_id}/reassess-plan",
        response_model=ContinuousReassessmentPlan,
        tags=["Continuous"],
    )
    def compute_reassessment_plan(
        assessment_id: str,
        payload: ReassessmentPlanRequest,
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("operator")),
    ) -> ContinuousReassessmentPlan:
        res, _ = _load_or_404(request, assessment_id)
        return ContinuousEvidenceTracker().compute_reassessment_plan(
            res,
            current_target_path=payload.current_target_path,
            updated_sbom_package_versions=payload.updated_sbom_package_versions,
            new_advisory_vulns=payload.new_advisory_vulns,
        )

    @app.get(
        "/api/v1/integrations",
        response_model=list[IntegrationDescriptor],
        tags=["Integrations"],
    )
    def list_integrations(
        request: Request,
        _principal: AuthPrincipal = Depends(require_role("viewer")),
    ) -> list[IntegrationDescriptor]:
        registry: IntegrationRegistry = request.app.state.integration_registry
        return registry.inspect_all(request.app.state.settings)

    @app.post(
        "/api/v1/webhooks/ci",
        response_model=WebhookCIResponse,
        tags=["Integrations"],
    )
    def receive_ci_webhook(
        payload: WebhookCIRequest,
        request: Request,
        principal: AuthPrincipal = Depends(require_role("operator")),
    ) -> WebhookCIResponse:
        plan = None
        if payload.assessment_id:
            res, _ = _load_or_404(request, payload.assessment_id)
            plan = ContinuousEvidenceTracker().compute_reassessment_plan(
                res,
                updated_sbom_package_versions=payload.updated_sbom_package_versions,
            )
        request.app.state.audit_logger.log(
            principal=principal,
            action="ci_webhook",
            resource=f"repo:{payload.repository}",
            status_code=200,
            detail=f"event={payload.event_type}",
        )
        return WebhookCIResponse(
            accepted=True,
            event_type=payload.event_type,
            reassessment_plan=plan,
            note="CI event processed via ContinuousEvidenceTracker without duplicating analysis engines.",
        )

    @app.get(
        "/api/v1/audit-logs",
        response_model=list[AuditLogEntryResponse],
        tags=["Governance"],
    )
    def list_audit_logs(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        _principal: AuthPrincipal = Depends(require_role("admin")),
    ) -> list[AuditLogEntryResponse]:
        rows = request.app.state.audit_logger.list_recent(limit=limit)
        return [AuditLogEntryResponse(**row) for row in rows]

    return app


app = create_app()
