"""Persistent job store, background assessment execution, and non-conflated API query service."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from apps.api.schemas import (
    AssessmentCreateRequest,
    AssessmentSummaryItem,
    JobStatusResponse,
    VulnerabilityNonConflatedView,
)
from packages.core.analysis import run_hybrid_reachability_discovery
from packages.core.analysis.python import (
    load_entry_point_config,
    load_symbol_manifest,
)
from packages.core.config.settings import Settings
from packages.core.engines.ai_intelligence import AISecurityIntelligenceOrchestrator
from packages.core.engines.attack_path import AttackPathOrchestrator
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.engines.openvex import OpenVEXOrchestrator
from packages.core.engines.risk import RiskIntelligenceOrchestrator
from packages.core.integrations.threat_feeds import ThreatFeedClient
from packages.core.models.attack_path import AttackPathRecord
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.intelligence import VulnerabilityIntelligence
from packages.core.models.openvex import VEXPolicyDecision
from packages.core.models.reachability import ReachabilityResult, ReachabilityState
from packages.core.models.risk import VulnerabilityRiskAssessment
from packages.core.storage.evidence_store import EvidenceStore
from packages.core.storage.vex_history import SQLiteVEXStore


class SQLiteJobStore:
    """Persists asynchronous backend assessment jobs in SQLite."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_jobs (
                    job_id TEXT PRIMARY KEY,
                    assessment_id TEXT,
                    target_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT
                )
                """
            )

    def create_job(self, target_path: str) -> JobStatusResponse:
        now = datetime.now(timezone.utc)
        job = JobStatusResponse(
            job_id=str(uuid4()),
            target_path=target_path,
            status="queued",
            created_at=now,
        )
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO assessment_jobs (job_id, assessment_id, target_path, status, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (job.job_id, None, target_path, job.status, now.isoformat()),
            )
        return job

    def update_job(
        self,
        job_id: str,
        *,
        status: str,
        assessment_id: str | None = None,
        error: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        started = now if status == "running" else None
        completed = now if status in {"completed", "failed"} else None
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                UPDATE assessment_jobs
                SET status = ?,
                    assessment_id = COALESCE(?, assessment_id),
                    started_at = COALESCE(?, started_at),
                    completed_at = COALESCE(?, completed_at),
                    error = ?
                WHERE job_id = ?
                """,
                (status, assessment_id, started, completed, error, job_id),
            )

    def get_job(self, job_id: str) -> JobStatusResponse | None:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM assessment_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        if row is None:
            return None
        return JobStatusResponse(
            job_id=row["job_id"],
            assessment_id=row["assessment_id"],
            target_path=row["target_path"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=(
                datetime.fromisoformat(row["started_at"]) if row["started_at"] else None
            ),
            completed_at=(
                datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
            ),
            error=row["error"],
        )


def list_persisted_assessments(
    evidence_store: EvidenceStore,
) -> list[tuple[DiscoveryResult, Path]]:
    """Scan configured evidence store directory safely for persisted DiscoveryResult reports."""
    base = evidence_store.base_output_dir
    if not base.is_dir():
        return []

    found: list[tuple[DiscoveryResult, Path]] = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        json_file = entry / "discovery-assessment.json"
        if not json_file.is_file():
            continue
        try:
            res = DiscoveryResult.model_validate_json(
                json_file.read_text(encoding="utf-8")
            )
            found.append((res, entry))
        except Exception:
            continue
    found.sort(key=lambda item: item[0].scan_metadata.scan_started_at, reverse=True)
    return found


def build_assessment_summary(res: DiscoveryResult) -> AssessmentSummaryItem:
    return AssessmentSummaryItem(
        assessment_id=res.assessment_id,
        target_path=res.target.target_path,
        scan_status=res.scan_metadata.scan_status.value,
        sbom_completeness=res.sbom.completeness_status.value,
        packages_count=len(res.packages),
        vulnerabilities_count=len(res.vulnerabilities),
        has_intelligence=res.intelligence is not None,
        has_reachability=res.reachability is not None,
        has_attack_paths=res.attack_paths is not None,
        has_risk=res.risk_assessment is not None,
        has_openvex=res.policy_evaluation is not None,
        scan_started_at=res.scan_metadata.scan_started_at,
        scan_completed_at=res.scan_metadata.scan_completed_at,
    )


def build_non_conflated_vulnerabilities(
    res: DiscoveryResult,
) -> list[VulnerabilityNonConflatedView]:
    """Assemble explicit non-conflated per-vulnerability views across all backend engines."""
    pkg_by_id = {p.package_id: p for p in res.packages}
    intel_by_vid: dict[str, VulnerabilityIntelligence] = (
        {v.vulnerability_id: v for v in res.intelligence.vulnerabilities}
        if res.intelligence is not None
        else {}
    )
    reach_by_vid: dict[str, list[ReachabilityResult]] = {}
    if res.reachability is not None:
        for rr in res.reachability.results:
            reach_by_vid.setdefault(rr.vulnerability_id, []).append(rr)

    ap_by_vid: dict[str, list[AttackPathRecord]] = {}
    if res.attack_paths is not None:
        for ap in res.attack_paths.paths:
            ap_by_vid.setdefault(ap.vulnerability_id, []).append(ap)

    risk_by_vid: dict[str, VulnerabilityRiskAssessment] = (
        {a.vulnerability_id: a for a in res.risk_assessment.assessments}
        if res.risk_assessment is not None
        else {}
    )
    vex_by_vid: dict[str, VEXPolicyDecision] = (
        {d.vulnerability_id: d for d in res.policy_evaluation.decisions}
        if res.policy_evaluation is not None
        else {}
    )
    rt_matched = (
        set(res.runtime_evidence.matched_vulnerability_ids)
        if res.runtime_evidence is not None
        else set()
    )

    views: list[VulnerabilityNonConflatedView] = []
    for vuln in res.vulnerabilities:
        pkg = pkg_by_id.get(vuln.package_id)
        intel = intel_by_vid.get(vuln.vulnerability_id)
        reaches = reach_by_vid.get(vuln.vulnerability_id, [])
        aps = ap_by_vid.get(vuln.vulnerability_id, [])
        risk = risk_by_vid.get(vuln.vulnerability_id)
        vex = vex_by_vid.get(vuln.vulnerability_id)

        cand_syms = [
            r.candidate_symbol.qualified_name for r in reaches if r.candidate_symbol
        ]
        any_reachable = any(r.state == ReachabilityState.REACHABLE for r in reaches)
        all_no_path = bool(reaches) and all(
            r.state == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET for r in reaches
        )
        static_path_flag: bool | None = (
            True if any_reachable else (False if all_no_path else None)
        )
        reach_state_str = (
            ReachabilityState.REACHABLE.value
            if any_reachable
            else (reaches[0].state.value if reaches else None)
        )
        incomplete_flag = bool(
            res.reachability is None
            or res.reachability.truncated
            or res.reachability.files_failed > 0
            or any(
                r.state
                in {ReachabilityState.UNRESOLVED, ReachabilityState.ANALYSIS_INCOMPLETE}
                for r in reaches
            )
        )
        ev_insufficient = not cand_syms or not reaches or (
            risk.evidence_insufficient if risk else False
        )
        fixed_versions = (
            list(intel.fixed_versions)
            if intel and intel.fixed_versions
            else ([vuln.fixed_version] if vuln.fixed_version else [])
        )

        views.append(
            VulnerabilityNonConflatedView(
                vulnerability_id=vuln.vulnerability_id,
                canonical_id=intel.canonical_id if intel else vuln.vulnerability_id,
                aliases=list(intel.aliases) if intel else [],
                package_id=vuln.package_id,
                package_name=pkg.name if pkg else vuln.package_id,
                package_version=pkg.version if pkg else None,
                ecosystem=pkg.ecosystem if pkg else "unknown",
                severity=vuln.severity.value,
                fixed_versions=fixed_versions,
                vulnerable_dependency_detected=True,
                candidate_symbol_identified=bool(cand_syms),
                candidate_symbols=cand_syms,
                static_path_identified=static_path_flag,
                reachability_state=reach_state_str,
                runtime_execution_observed=(
                    True if vuln.vulnerability_id in rt_matched else None
                ),
                analysis_incomplete=incomplete_flag,
                evidence_insufficient=ev_insufficient,
                exploitability_established=False,
                attack_surface=aps[0].exposure_surface.value if aps else None,
                data_flow_status=aps[0].data_flow_status.value if aps else None,
                contextual_risk_score=risk.contextual_score if risk else None,
                risk_priority_tier=risk.priority_tier.value if risk else None,
                openvex_status=vex.decided_status.value if vex else None,
                openvex_justification=(
                    vex.justification.value if vex and vex.justification else None
                ),
            )
        )
    return views


def execute_assessment_pipeline_job(
    *,
    job_id: str,
    request: AssessmentCreateRequest,
    settings: Settings,
    job_store: SQLiteJobStore,
    evidence_store: EvidenceStore,
    trivy_client: Any = None,
) -> None:
    """Execute full configured backend pipeline safely for an API assessment job."""
    job_store.update_job(job_id, status="running")
    try:
        disc_orch = DiscoveryOrchestrator(
            settings=settings,
            evidence_store=evidence_store,
            trivy_client=trivy_client,
        )
        result, artifacts = disc_orch.run_discovery(target_path=request.target_path)
        if artifacts is None:
            job_store.update_job(
                job_id,
                status="failed",
                assessment_id=result.assessment_id,
                error="; ".join(result.errors) or "Discovery failed to initialize artifacts.",
            )
            return

        if request.enrich_osv:
            with IntelligenceOrchestrator(
                settings=settings, evidence_store=evidence_store
            ) as intel_orch:
                result = intel_orch.enrich(discovery_result=result, artifacts=artifacts)

        dep_dirs = [Path(p) for p in request.dependency_source_dirs] if request.dependency_source_dirs else None
        ai_manifest = None
        if request.extract_symbols:
            with AISecurityIntelligenceOrchestrator(
                settings=settings, dependency_source_dirs=dep_dirs
            ) as ai_orch:
                result, ai_report, raw_patch = ai_orch.analyze_discovery_result(
                    result,
                    patch_dir=Path(request.patch_dir) if request.patch_dir else None,
                )
                ai_manifest = ai_report.generated_manifest
                evidence_store.persist_ai_intelligence_artifacts(
                    artifacts, ai_report, raw_patch_payloads=raw_patch
                )
                evidence_store.persist_assessment(artifacts=artifacts, result=result)

        if request.analyze_python or request.analyze_go or request.attack_paths:
            loaded_manifest = None
            manifest_sha = None
            loaded_ep = None
            if request.symbols_file:
                loaded_manifest, manifest_sha = load_symbol_manifest(request.symbols_file)
            elif ai_manifest is not None:
                loaded_manifest = ai_manifest
            if request.entry_points_file:
                loaded_ep = load_entry_point_config(request.entry_points_file)

            result, reach_bundle = run_hybrid_reachability_discovery(
                result,
                target_path=request.target_path,
                analyze_python=request.analyze_python,
                analyze_go=request.analyze_go,
                settings=settings,
                manifest=loaded_manifest,
                manifest_sha256=manifest_sha,
                entry_point_config=loaded_ep,
                dependency_source_dirs=dep_dirs,
            )
            evidence_store.persist_reachability_artifacts(
                artifacts,
                reach_bundle.report,
                call_graph_artifact=reach_bundle.call_graph_artifact,
                manifest=reach_bundle.manifest,
            )
            evidence_store.persist_assessment(artifacts=artifacts, result=result)

        if request.attack_paths:
            result, ap_report = AttackPathOrchestrator(
                settings=settings
            ).analyze_discovery_result(result, target_path=request.target_path)
            evidence_store.persist_attack_path_artifacts(artifacts, ap_report)
            evidence_store.persist_assessment(artifacts=artifacts, result=result)

        if request.compute_risk:
            with ThreatFeedClient(settings=settings) as feed_client:
                snap = feed_client.load_snapshot(
                    [v.vulnerability_id for v in result.vulnerabilities],
                    fetch_remote=False,
                )
            result, risk_report = RiskIntelligenceOrchestrator().evaluate(
                result,
                threat_snapshot=snap,
                workload_context=request.workload_context,
            )
            evidence_store.persist_risk_artifacts(artifacts, risk_report)
            evidence_store.persist_assessment(artifacts=artifacts, result=result)

        if request.emit_vex:
            result, _ = OpenVEXOrchestrator(
                settings=settings,
                vex_history_store=SQLiteVEXStore(settings.storage_path),
                evidence_store=evidence_store,
            ).generate(result, artifacts=artifacts)

        job_store.update_job(
            job_id,
            status="completed",
            assessment_id=result.assessment_id,
        )
    except Exception as exc:
        job_store.update_job(
            job_id,
            status="failed",
            error=str(exc),
        )
