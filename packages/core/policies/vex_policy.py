"""Deterministic, fail-closed OpenVEX status evaluation policy (Milestone 5)."""

from __future__ import annotations

from datetime import datetime, timezone

from packages.core.models.attack_path import AttackPathRecord
from packages.core.models.discovery import (
    DiscoveryResult,
    PackageRecord,
    SBOMCompletenessStatus,
    ScanStatus,
    VulnerabilityRecord,
)
from packages.core.models.intelligence import (
    CorrelationOutcome,
    IntelligenceStatus,
    VersionMatchStatus,
    VulnerabilityIntelligence,
)
from packages.core.models.openvex import (
    EvidenceCompletenessReport,
    OpenVEXDocument,
    OpenVEXPolicyReport,
    VEXJustification,
    VEXPolicyDecision,
    VEXStatement,
    VEXStatus,
)
from packages.core.models.reachability import (
    DependencySymbolResolutionStatus,
    ReachabilityResult,
    ReachabilityState,
)


def evaluate_vex_policy(
    discovery_result: DiscoveryResult,
    *,
    document_version: int = 1,
    author: str = "VEXReach Deterministic Policy Engine",
    runtime_observations: dict[str, list[str]] | None = None,
) -> OpenVEXPolicyReport:
    """Deterministically evaluate accumulated evidence into OpenVEX 0.2.0 statements.

    Security invariants enforced:
    - Never emits `not_affected` if SBOM/scan is incomplete, intelligence errored or conflicts,
      dependency symbol verification failed/unavailable, unresolved calls exist, or static
      analysis was incomplete/truncated.
    - Never uses LLM outputs directly to determine security status; only verified/correlated
      deterministic facts and bounded static reachability results govern VEX status.
    - Absence of runtime observations never triggers `not_affected`.
    """
    blocking_gaps: list[str] = []
    scan_completed = discovery_result.scan_metadata.scan_status == ScanStatus.COMPLETED
    if not scan_completed:
        blocking_gaps.append(
            f"Scanner status is '{discovery_result.scan_metadata.scan_status.value}', not 'completed'."
        )

    sbom_complete = discovery_result.sbom.completeness_status == SBOMCompletenessStatus.COMPLETE
    if not sbom_complete:
        blocking_gaps.append(
            f"SBOM completeness status is '{discovery_result.sbom.completeness_status.value}', not 'complete'."
        )

    intel_report = discovery_result.intelligence
    intel_checked = intel_report is not None
    intel_conflict_free = True
    if intel_report is None:
        blocking_gaps.append("OSV advisory intelligence enrichment was not run.")
    else:
        if intel_report.intelligence_status == IntelligenceStatus.FAILED:
            intel_conflict_free = False
            blocking_gaps.append("OSV intelligence enrichment failed.")
        if intel_report.conflicting_records > 0:
            intel_conflict_free = False
            blocking_gaps.append(
                f"OSV intelligence detected {intel_report.conflicting_records} conflicting record(s)."
            )

    reach_report = discovery_result.reachability
    reach_executed = reach_report is not None
    reach_complete = False
    has_verified_dep_sources = False
    if reach_report is None:
        blocking_gaps.append("Python static reachability analysis was not executed.")
    else:
        reach_complete = (
            reach_report.files_failed == 0
            and not reach_report.truncated
            and len([ep for ep in reach_report.entry_points if ep.confidence != "unresolved"]) > 0
        )
        if not reach_complete:
            blocking_gaps.append(
                "Static reachability analysis hit truncation limits, parse failures, or lacked resolved entry points."
            )
        has_verified_dep_sources = any(
            r.dependency_symbol_status == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE
            for r in reach_report.results
        )

    completeness = EvidenceCompletenessReport(
        scan_completed=scan_completed,
        sbom_complete=sbom_complete,
        intelligence_checked=intel_checked,
        intelligence_conflict_free=intel_conflict_free,
        reachability_executed=reach_executed,
        reachability_complete_without_truncation=reach_complete,
        dependency_sources_verified=has_verified_dep_sources,
        blocking_gaps=blocking_gaps,
    )

    pkg_by_id = {p.package_id: p for p in discovery_result.packages}
    intel_by_vid = (
        {v.vulnerability_id: v for v in intel_report.vulnerabilities}
        if intel_report is not None
        else {}
    )
    reach_by_vid: dict[str, list[ReachabilityResult]] = {}
    if reach_report is not None:
        for rr in reach_report.results:
            reach_by_vid.setdefault(rr.vulnerability_id, []).append(rr)

    ap_by_vid: dict[str, list[AttackPathRecord]] = {}
    if discovery_result.attack_paths is not None:
        for ap in discovery_result.attack_paths.paths:
            ap_by_vid.setdefault(ap.vulnerability_id, []).append(ap)

    statements: list[VEXStatement] = []
    decisions: list[VEXPolicyDecision] = []
    warnings: list[str] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    runtime_map = runtime_observations or {}

    for vuln in discovery_result.vulnerabilities:
        pkg = pkg_by_id.get(vuln.package_id)
        intel = intel_by_vid.get(vuln.vulnerability_id)
        reach_list = reach_by_vid.get(vuln.vulnerability_id, [])
        ap_list = ap_by_vid.get(vuln.vulnerability_id, [])
        rt_obs = runtime_map.get(vuln.vulnerability_id, [])

        decision, statement = _evaluate_single_vulnerability(
            vuln=vuln,
            pkg=pkg,
            intel=intel,
            reach_list=reach_list,
            ap_list=ap_list,
            rt_obs=rt_obs,
            completeness=completeness,
            now_iso=now_iso,
        )
        decisions.append(decision)
        statements.append(statement)

    if not discovery_result.vulnerabilities:
        warnings.append("DiscoveryResult contained 0 vulnerability findings; emitted empty OpenVEX statements list.")

    doc = OpenVEXDocument(
        author=author,
        timestamp=now_iso,
        version=document_version,
        statements=statements,
    )
    counts = {s.value: 0 for s in VEXStatus}
    for st in statements:
        counts[st.status.value] += 1

    return OpenVEXPolicyReport(
        target_path=discovery_result.target.target_path,
        openvex_document=doc,
        completeness=completeness,
        decisions=decisions,
        status_counts=counts,
        warnings=warnings,
    )


def _evaluate_single_vulnerability(
    *,
    vuln: VulnerabilityRecord,
    pkg: PackageRecord | None,
    intel: VulnerabilityIntelligence | None,
    reach_list: list[ReachabilityResult],
    ap_list: list[AttackPathRecord],
    rt_obs: list[str],
    completeness: EvidenceCompletenessReport,
    now_iso: str,
) -> tuple[VEXPolicyDecision, VEXStatement]:
    pkg_name = pkg.name if pkg else vuln.package_id
    product_id = (
        pkg.purl
        if pkg and pkg.purl
        else (
            f"pkg:{pkg.ecosystem.lower()}/{pkg.name}@{pkg.version or 'unknown'}"
            if pkg
            else vuln.package_id
        )
    )
    vuln_obj: dict[str, object] = {"name": vuln.vulnerability_id}
    if intel is not None:
        if intel.aliases:
            vuln_obj["aliases"] = list(intel.aliases)
        if intel.canonical_id != vuln.vulnerability_id:
            vuln_obj["@id"] = intel.canonical_id

    evidence_ids = list(vuln.references[:3])
    if intel is not None:
        evidence_ids.extend(intel.source_records[:3])
    evidence_ids = list(dict.fromkeys(evidence_ids))

    fixed_hint = _format_fix_hint(vuln=vuln, intel=intel)
    uncertainty_notes: list[str] = []

    # Rule 1: Any statically REACHABLE candidate symbol -> AFFECTED
    reachable_hits = [r for r in reach_list if r.state == ReachabilityState.REACHABLE]
    if reachable_hits:
        best = reachable_hits[0]
        ap_summary = ""
        if ap_list:
            ap = ap_list[0]
            ap_summary = (
                f" Attack surface={ap.exposure_surface.value}, "
                f"data_flow={ap.data_flow_status.value}."
            )
        rt_note = (
            f" Runtime observations also recorded: {rt_obs}."
            if rt_obs
            else " Static reachability path found; runtime execution is separate/unobserved."
        )
        action = (
            f"Static call path reaches vulnerable symbol '{best.candidate_symbol.qualified_name if best.candidate_symbol else 'unknown'}' "
            f"via {' -> '.join(best.path)}.{ap_summary} {fixed_hint}"
        ).strip()
        statement = VEXStatement(
            vulnerability=vuln_obj,
            products=[product_id],
            status=VEXStatus.AFFECTED,
            action_statement=action,
            action_statement_timestamp=now_iso,
            status_notes=f"Rule=STATIC_PATH_REACHABLE.{rt_note}",
            timestamp=now_iso,
        )
        decision = VEXPolicyDecision(
            vulnerability_id=vuln.vulnerability_id,
            package_name=pkg_name,
            product_identifier=product_id,
            decided_status=VEXStatus.AFFECTED,
            confidence="high",
            decision_rule="RULE_01_STATIC_REACHABLE_PATH",
            rationale=action,
            supporting_evidence_ids=evidence_ids,
            uncertainty_notes=uncertainty_notes,
        )
        return decision, statement

    # Rule 2: Advisory intelligence conflict or incomplete intelligence -> UNDER_INVESTIGATION
    if intel is not None and intel.overall_correlation == CorrelationOutcome.CONFLICTING_EVIDENCE:
        uncertainty_notes.append(
            "Trivy scanner reported finding while OSV version evaluation reported NOT_AFFECTED/conflicting evidence."
        )
        note = "Conflict between scanner and advisory ranges preserves under_investigation status."
        return _under_investigation(
            vuln=vuln,
            vuln_obj=vuln_obj,
            pkg_name=pkg_name,
            product_id=product_id,
            now_iso=now_iso,
            rule="RULE_02_ADVISORY_SCANNER_CONFLICT",
            rationale=note,
            evidence_ids=evidence_ids,
            uncertainty_notes=uncertainty_notes,
        )

    # Rule 3: Runtime observation without static path -> still conservative AFFECTED / UNDER_INVESTIGATION (never not_affected)
    if rt_obs:
        action = (
            f"Runtime execution trace observed vulnerable symbol(s) {rt_obs}; "
            f"requires remediation regardless of missing static path. {fixed_hint}"
        ).strip()
        statement = VEXStatement(
            vulnerability=vuln_obj,
            products=[product_id],
            status=VEXStatus.AFFECTED,
            action_statement=action,
            action_statement_timestamp=now_iso,
            status_notes="Rule=RUNTIME_OBSERVATION_CONFIRMED",
            timestamp=now_iso,
        )
        return (
            VEXPolicyDecision(
                vulnerability_id=vuln.vulnerability_id,
                package_name=pkg_name,
                product_identifier=product_id,
                decided_status=VEXStatus.AFFECTED,
                confidence="high",
                decision_rule="RULE_03_RUNTIME_OBSERVATION",
                rationale=action,
                supporting_evidence_ids=evidence_ids,
            ),
            statement,
        )

    # Rule 4: Non-Python or unanalyzed finding -> UNDER_INVESTIGATION
    if not reach_list:
        uncertainty_notes.append("No static reachability evaluation results available for this finding.")
        return _under_investigation(
            vuln=vuln,
            vuln_obj=vuln_obj,
            pkg_name=pkg_name,
            product_id=product_id,
            now_iso=now_iso,
            rule="RULE_04_NO_REACHABILITY_RESULTS",
            rationale="Static reachability analysis produced no evaluation for this finding (non-Python ecosystem or skipped).",
            evidence_ids=evidence_ids,
            uncertainty_notes=uncertainty_notes,
        )

    # Rule 5: Strict completeness check before EVER permitting NOT_AFFECTED
    blockers: list[str] = []
    if not completeness.scan_completed:
        blockers.append("Scan did not complete cleanly.")
    if not completeness.sbom_complete:
        blockers.append("SBOM is not marked COMPLETE.")
    if intel is not None and intel.intelligence_status == IntelligenceStatus.FAILED:
        blockers.append("OSV intelligence enrichment failed.")

    all_no_path = all(
        r.state == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET for r in reach_list
    )
    all_dep_verified = all(
        r.dependency_symbol_status
        == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE
        for r in reach_list
    )
    any_unresolved_calls = any(len(r.unresolved_calls) > 0 for r in reach_list)

    if not all_no_path:
        states = sorted({r.state.value for r in reach_list})
        blockers.append(f"Reachability states include non-negative outcome(s): {states}.")
    if not all_dep_verified:
        blockers.append(
            "Candidate vulnerable symbol(s) were not deterministically verified against dependency source AST."
        )
    if any_unresolved_calls:
        blockers.append("Entry-reachable unresolved dynamic calls prevent ruling out execution.")
    if not completeness.reachability_complete_without_truncation:
        blockers.append(
            "Static call-graph analysis reported truncation, file parse failure, or missing entry points."
        )

    if not blockers:
        syms = [
            r.candidate_symbol.qualified_name
            for r in reach_list
            if r.candidate_symbol is not None
        ]
        impact = (
            f"Complete static AST call-graph analysis found no path from resolved application entry points "
            f"to dependency-AST-verified vulnerable symbol(s) {syms}, with complete SBOM and zero unresolved dynamic calls."
        )
        statement = VEXStatement(
            vulnerability=vuln_obj,
            products=[product_id],
            status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            impact_statement=impact,
            status_notes="Rule=STRICT_COMPLETE_STATIC_NOT_IN_EXECUTE_PATH",
            timestamp=now_iso,
        )
        decision = VEXPolicyDecision(
            vulnerability_id=vuln.vulnerability_id,
            package_name=pkg_name,
            product_identifier=product_id,
            decided_status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            confidence="high",
            decision_rule="RULE_05_VERIFIED_NOT_IN_EXECUTE_PATH",
            rationale=impact,
            supporting_evidence_ids=evidence_ids,
        )
        return decision, statement

    # Otherwise fail conservatively to UNDER_INVESTIGATION
    uncertainty_notes.extend(blockers)
    return _under_investigation(
        vuln=vuln,
        vuln_obj=vuln_obj,
        pkg_name=pkg_name,
        product_id=product_id,
        now_iso=now_iso,
        rule="RULE_06_CONSERVATIVE_UNDER_INVESTIGATION",
        rationale="Cannot emit 'not_affected' cleanly: " + " ".join(blockers),
        evidence_ids=evidence_ids,
        uncertainty_notes=uncertainty_notes,
    )


def _under_investigation(
    *,
    vuln: VulnerabilityRecord,
    vuln_obj: dict[str, object],
    pkg_name: str,
    product_id: str,
    now_iso: str,
    rule: str,
    rationale: str,
    evidence_ids: list[str],
    uncertainty_notes: list[str],
) -> tuple[VEXPolicyDecision, VEXStatement]:
    statement = VEXStatement(
        vulnerability=vuln_obj,
        products=[product_id],
        status=VEXStatus.UNDER_INVESTIGATION,
        status_notes=f"{rule}: {rationale}",
        timestamp=now_iso,
    )
    decision = VEXPolicyDecision(
        vulnerability_id=vuln.vulnerability_id,
        package_name=pkg_name,
        product_identifier=product_id,
        decided_status=VEXStatus.UNDER_INVESTIGATION,
        confidence="low",
        decision_rule=rule,
        rationale=rationale,
        supporting_evidence_ids=evidence_ids,
        uncertainty_notes=uncertainty_notes,
    )
    return decision, statement


def _format_fix_hint(
    *, vuln: VulnerabilityRecord, intel: VulnerabilityIntelligence | None
) -> str:
    versions: list[str] = []
    if intel is not None and intel.fixed_versions:
        versions.extend(intel.fixed_versions)
    elif vuln.fixed_version:
        versions.append(vuln.fixed_version)
    if versions:
        return f"Upgrade to fixed version(s): {', '.join(versions)}."
    return "No upstream fixed version metadata available; apply compensating controls."
