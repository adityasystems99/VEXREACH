"""Deterministic explainable contextual risk scoring (Engine 5)."""

from __future__ import annotations

from packages.core.integrations.threat_feeds.client import ThreatFeedSnapshot
from packages.core.models.attack_path import AttackPathRecord, ExposureSurface, TaintFlowStatus
from packages.core.models.discovery import (
    DiscoveryResult,
    PackageRecord,
    SBOMCompletenessStatus,
    ScanStatus,
    SeverityLevel,
    VulnerabilityRecord,
)
from packages.core.models.intelligence import CorrelationOutcome, VulnerabilityIntelligence
from packages.core.models.reachability import (
    DependencySymbolResolutionStatus,
    ReachabilityResult,
    ReachabilityState,
)
from packages.core.models.risk import (
    RiskIntelligenceReport,
    RiskPriorityTier,
    ScoreFactorContribution,
    ThreatIntelligenceSignals,
    VulnerabilityRiskAssessment,
    WorkloadContext,
)
from packages.core.utils.logging import get_logger

logger = get_logger("risk.orchestrator")

_SEVERITY_FALLBACK_CVSS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 9.0,
    SeverityLevel.HIGH: 7.5,
    SeverityLevel.MEDIUM: 5.0,
    SeverityLevel.LOW: 2.5,
    SeverityLevel.NEGLIGIBLE: 0.5,
    SeverityLevel.UNKNOWN: 5.0,
}


class RiskIntelligenceOrchestrator:
    """Computes explainable deterministic risk prioritization without LLM verdicts."""

    def evaluate(
        self,
        discovery_result: DiscoveryResult,
        *,
        threat_snapshot: ThreatFeedSnapshot | None = None,
        workload_context: WorkloadContext | None = None,
        runtime_observations: dict[str, list[str]] | None = None,
    ) -> tuple[DiscoveryResult, RiskIntelligenceReport]:
        """Score all vulnerabilities in `discovery_result` deterministically."""
        snap = threat_snapshot or ThreatFeedSnapshot()
        ctx = workload_context or WorkloadContext()
        rt_map = runtime_observations or {}

        pkg_by_id = {p.package_id: p for p in discovery_result.packages}
        intel_by_vid = (
            {v.vulnerability_id: v for v in discovery_result.intelligence.vulnerabilities}
            if discovery_result.intelligence is not None
            else {}
        )
        reach_by_vid: dict[str, list[ReachabilityResult]] = {}
        if discovery_result.reachability is not None:
            for rr in discovery_result.reachability.results:
                reach_by_vid.setdefault(rr.vulnerability_id, []).append(rr)

        ap_by_vid: dict[str, list[AttackPathRecord]] = {}
        if discovery_result.attack_paths is not None:
            for ap in discovery_result.attack_paths.paths:
                ap_by_vid.setdefault(ap.vulnerability_id, []).append(ap)

        assessments: list[VulnerabilityRiskAssessment] = []
        kev_matches = 0
        priority_counts = {tier.value: 0 for tier in RiskPriorityTier}

        for vuln in discovery_result.vulnerabilities:
            pkg = pkg_by_id.get(vuln.package_id)
            intel = intel_by_vid.get(vuln.vulnerability_id)
            item = self._score_vulnerability(
                discovery_result=discovery_result,
                vuln=vuln,
                pkg=pkg,
                intel=intel,
                reach_list=reach_by_vid.get(vuln.vulnerability_id, []),
                ap_list=ap_by_vid.get(vuln.vulnerability_id, []),
                snap=snap,
                ctx=ctx,
                rt_obs=rt_map.get(vuln.vulnerability_id, []),
            )
            if item.threat_signals.in_cisa_kev:
                kev_matches += 1
            priority_counts[item.priority_tier.value] += 1
            assessments.append(item)

        assessments.sort(key=lambda a: (-a.contextual_score, a.vulnerability_id))

        report = RiskIntelligenceReport(
            workload_context=ctx,
            findings_scored=len(assessments),
            kev_matches=kev_matches,
            priority_counts=priority_counts,
            assessments=assessments,
            warnings=list(snap.warnings),
        )
        updated = discovery_result.model_copy(update={"risk_assessment": report})
        logger.info(
            "Risk Intelligence scored %d findings (kev_matches=%d, priority_counts=%s)",
            len(assessments),
            kev_matches,
            priority_counts,
        )
        return updated, report

    def _score_vulnerability(
        self,
        *,
        discovery_result: DiscoveryResult,
        vuln: VulnerabilityRecord,
        pkg: PackageRecord | None,
        intel: VulnerabilityIntelligence | None,
        reach_list: list[ReachabilityResult],
        ap_list: list[AttackPathRecord],
        snap: ThreatFeedSnapshot,
        ctx: WorkloadContext,
        rt_obs: list[str],
    ) -> VulnerabilityRiskAssessment:
        pkg_name = pkg.name if pkg else vuln.package_id
        eco = pkg.ecosystem if pkg else "unknown"
        breakdown: list[ScoreFactorContribution] = []
        assumptions: list[str] = []

        # 1. Resolve canonical CVE for EPSS / KEV matching
        cve_id = _pick_cve_id(vuln, intel)
        epss_rec = snap.epss_by_cve.get(cve_id)
        kev_rec = snap.kev_by_cve.get(cve_id)
        threat_sources: list[str] = []
        threat_warnings: list[str] = []
        if epss_rec is not None:
            threat_sources.append("FIRST_EPSS")
        else:
            threat_warnings.append("EPSS score unavailable offline/for identifier; no synthetic probability assumed.")
        if snap.kev_loaded:
            threat_sources.append("CISA_KEV")
        else:
            threat_warnings.append("CISA KEV catalog not loaded.")

        threat_signals = ThreatIntelligenceSignals(
            cve_id=cve_id,
            epss_score=epss_rec.epss if epss_rec else None,
            epss_percentile=epss_rec.percentile if epss_rec else None,
            in_cisa_kev=(kev_rec is not None) if snap.kev_loaded else None,
            kev_date_added=kev_rec.date_added if kev_rec else None,
            kev_due_date=kev_rec.due_date if kev_rec else None,
            kev_known_ransomware_use=kev_rec.known_ransomware_use if kev_rec else None,
            sources_consulted=threat_sources,
            warnings=threat_warnings,
        )

        # 2. Base Severity / CVSS (0-35 pts)
        cvss_scores = [m.base_score for m in vuln.cvss if m.base_score is not None]
        best_cvss = max(cvss_scores) if cvss_scores else None
        effective_cvss = (
            best_cvss
            if best_cvss is not None
            else _SEVERITY_FALLBACK_CVSS.get(vuln.severity, 5.0)
        )
        base_pts = round((effective_cvss / 10.0) * 35.0, 2)
        breakdown.append(
            ScoreFactorContribution(
                factor_name="cvss_base_severity",
                points=base_pts,
                rationale=(
                    f"CVSS score {best_cvss:.1f}/10 weighted to 35 pts."
                    if best_cvss is not None
                    else f"Missing CVSS vector; severity fallback '{vuln.severity.value}' ({effective_cvss:.1f}/10)."
                ),
                evidence_basis="discovery.cvss" if best_cvss is not None else "discovery.severity_fallback",
            )
        )

        # 3. KEV / EPSS exploitation threat intelligence (0-30 pts)
        if threat_signals.in_cisa_kev:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="cisa_kev_active_exploitation",
                    points=18.0,
                    rationale=f"{cve_id} appears in CISA Known Exploited Vulnerabilities catalog.",
                    evidence_basis="CISA_KEV",
                )
            )
        if threat_signals.epss_score is not None:
            epss_pts = round(threat_signals.epss_score * 12.0, 2)
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="epss_signal",
                    points=epss_pts,
                    rationale=f"EPSS score {threat_signals.epss_score:.4f} weighted cleanly to max 12 pts.",
                    evidence_basis="FIRST_EPSS",
                )
            )

        # 4. Separate fact tracking + reachability adjustment
        candidate_identified = any(r.candidate_symbol is not None for r in reach_list)
        any_reachable = any(r.state == ReachabilityState.REACHABLE for r in reach_list)
        any_unresolved = any(
            r.state in {ReachabilityState.UNRESOLVED, ReachabilityState.ANALYSIS_INCOMPLETE}
            for r in reach_list
        )
        all_no_path = bool(reach_list) and all(
            r.state == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET
            for r in reach_list
        )
        all_dep_verified = bool(reach_list) and all(
            r.dependency_symbol_status
            == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE
            for r in reach_list
        )
        reach_incomplete = (
            discovery_result.reachability is None
            or discovery_result.reachability.files_failed > 0
            or discovery_result.reachability.truncated
            or any_unresolved
        )
        scan_incomplete = (
            discovery_result.scan_metadata.scan_status != ScanStatus.COMPLETED
            or discovery_result.sbom.completeness_status != SBOMCompletenessStatus.COMPLETE
            or (intel is not None and intel.overall_correlation == CorrelationOutcome.CONFLICTING_EVIDENCE)
        )

        static_path_flag: bool | None
        if not reach_list or any_unresolved:
            static_path_flag = True if any_reachable else None
        elif any_reachable:
            static_path_flag = True
        elif all_no_path:
            static_path_flag = False
        else:
            static_path_flag = None

        rt_flag: bool | None = True if rt_obs else None

        if rt_obs:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="runtime_execution_observed",
                    points=20.0,
                    rationale=f"Runtime trace observed candidate symbol(s): {rt_obs}.",
                    evidence_basis="runtime_observations",
                )
            )
        elif any_reachable:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="static_reachability_path",
                    points=14.0,
                    rationale="Static call graph found at least one path from entry point to candidate vulnerable symbol.",
                    evidence_basis="reachability.state=reachable",
                )
            )
        elif all_no_path and all_dep_verified and not reach_incomplete and not scan_incomplete:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="verified_static_no_path_reduction",
                    points=-20.0,
                    rationale="Complete static AST call graph + verified dependency AST showed zero path with zero unresolved calls.",
                    evidence_basis="reachability.no_path_within_supported_subset+verified_dep_ast",
                )
            )
        elif any_unresolved or scan_incomplete:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="uncertainty_retention",
                    points=5.0,
                    rationale="Dynamic constructs, analysis truncation, conflicts, or incomplete SBOM keep elevated conservative priority.",
                    evidence_basis="analysis_uncertainty",
                )
            )

        # 5. Attack-path surface, taint, authentication, and workload criticality
        if ap_list:
            public_unauth = [
                a for a in ap_list if a.exposure_surface == ExposureSurface.NETWORK_HTTP_PUBLIC
            ]
            auth_net = [
                a for a in ap_list if a.exposure_surface == ExposureSurface.NETWORK_HTTP_AUTHENTICATED
            ]
            tainted = [
                a for a in ap_list if a.data_flow_status == TaintFlowStatus.TAINTED_FLOW_OBSERVED
            ]
            safe_barriers = [
                a for a in ap_list if a.data_flow_status == TaintFlowStatus.SANITIZED_OR_VALIDATED
            ]
            if public_unauth:
                breakdown.append(
                    ScoreFactorContribution(
                        factor_name="unauthenticated_network_exposure",
                        points=10.0,
                        rationale="Reachable via HTTP endpoint without statically detected handler auth barrier.",
                        evidence_basis="attack_path.exposure_surface",
                    )
                )
            elif auth_net:
                breakdown.append(
                    ScoreFactorContribution(
                        factor_name="authenticated_network_exposure",
                        points=4.0,
                        rationale="Reachable via authenticated HTTP endpoint (auth dependency/decorator detected).",
                        evidence_basis="attack_path.auth_barriers",
                    )
                )
            else:
                breakdown.append(
                    ScoreFactorContribution(
                        factor_name="local_cli_or_internal_exposure",
                        points=2.0,
                        rationale="Reachable via CLI or internal entrypoint without HTTP ingress.",
                        evidence_basis="attack_path.exposure_surface",
                    )
                )
            if tainted:
                breakdown.append(
                    ScoreFactorContribution(
                        factor_name="static_taint_propagation",
                        points=5.0,
                        rationale="Caller-controlled variable/parameter flow observed reaching sink arguments.",
                        evidence_basis="attack_path.data_flow_status=tainted_flow_observed",
                    )
                )
            elif safe_barriers:
                breakdown.append(
                    ScoreFactorContribution(
                        factor_name="sink_validation_barrier",
                        points=-4.0,
                        rationale="SafeLoader or validation barrier observed near sink; verify completeness.",
                        evidence_basis="attack_path.data_flow_status=sanitized_or_validated",
                    )
                )
        elif ctx.internet_facing:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="workload_internet_facing_context",
                    points=6.0,
                    rationale="Workload context declares service as internet-facing.",
                    evidence_basis="workload_context.internet_facing",
                )
            )

        crit_pts = {"critical": 5.0, "high": 2.5, "medium": 0.0, "low": -3.0}[ctx.criticality]
        if crit_pts != 0.0:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="workload_criticality",
                    points=crit_pts,
                    rationale=f"Declared workload criticality tier '{ctx.criticality}'.",
                    evidence_basis="workload_context.criticality",
                )
            )

        if ctx.mitigating_controls:
            breakdown.append(
                ScoreFactorContribution(
                    factor_name="declared_mitigating_controls",
                    points=-3.0,
                    rationale=f"Compensating controls declared: {ctx.mitigating_controls}.",
                    evidence_basis="workload_context.mitigating_controls",
                )
            )

        raw_score = sum(item.points for item in breakdown)
        contextual_score = round(min(100.0, max(0.0, raw_score)), 2)

        if (threat_signals.in_cisa_kev and any_reachable) or contextual_score >= 80.0:
            tier = RiskPriorityTier.P0_CRITICAL
        elif contextual_score >= 60.0:
            tier = RiskPriorityTier.P1_HIGH
        elif contextual_score >= 35.0:
            tier = RiskPriorityTier.P2_MEDIUM
        elif contextual_score >= 15.0:
            tier = RiskPriorityTier.P3_LOW
        else:
            tier = RiskPriorityTier.P4_MITIGATED

        evidence_insufficient = not candidate_identified or not reach_list or not all_dep_verified
        if evidence_insufficient:
            assumptions.append(
                "One or more verification layers (candidate symbol manifest, static reachability, or dependency AST verification) remain incomplete."
            )
        if not ctx.internet_facing and not ap_list:
            assumptions.append("No internet exposure declared or network HTTP attack path observed.")

        ev_quality = (
            "high"
            if (not scan_incomplete and not reach_incomplete and all_dep_verified and candidate_identified)
            else ("medium" if (reach_list and not scan_incomplete) else "low")
        )

        return VulnerabilityRiskAssessment(
            vulnerability_id=vuln.vulnerability_id,
            package_name=pkg_name,
            ecosystem=eco,
            contextual_score=contextual_score,
            priority_tier=tier,
            vulnerable_dependency_detected=True,
            candidate_symbol_identified=candidate_identified,
            static_path_identified=static_path_flag,
            runtime_execution_observed=rt_flag,
            analysis_incomplete=reach_incomplete or scan_incomplete,
            evidence_insufficient=evidence_insufficient,
            exploitability_established=False,
            cvss_base_score=best_cvss,
            threat_signals=threat_signals,
            evidence_quality=ev_quality,  # type: ignore[arg-type]
            score_breakdown=breakdown,
            assumptions=assumptions,
        )


def _pick_cve_id(
    vuln: VulnerabilityRecord, intel: VulnerabilityIntelligence | None
) -> str:
    if vuln.vulnerability_id.upper().startswith("CVE-"):
        return vuln.vulnerability_id.upper()
    if intel is not None:
        if intel.canonical_id.upper().startswith("CVE-"):
            return intel.canonical_id.upper()
        for alias in intel.aliases:
            if alias.upper().startswith("CVE-"):
                return alias.upper()
    return vuln.vulnerability_id
