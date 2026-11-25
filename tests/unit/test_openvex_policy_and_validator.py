"""Unit tests for OpenVEX 0.2.0 schema invariants and deterministic fail-closed policy."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from packages.core.engines.openvex import (
    validate_openvex_document,
    validate_openvex_json_payload,
)
from packages.core.models.discovery import (
    AssessmentTarget,
    DiscoveryResult,
    PackageRecord,
    SBOMCompletenessStatus,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
    VulnerabilityRecord,
)
from packages.core.models.intelligence import (
    CorrelationOutcome,
    IntelligenceStatus,
    VersionMatchStatus,
    VulnerabilityIntelligence,
    VulnerabilityIntelligenceReport,
)
from packages.core.models.openvex import VEXJustification, VEXStatement, VEXStatus
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    EntryPoint,
    ReachabilityResult,
    ReachabilityState,
    StaticReachabilityReport,
    SymbolConfidence,
    SymbolSource,
    UnresolvedCall,
    CodeLocation,
)
from packages.core.policies.vex_policy import evaluate_vex_policy


def _base_discovery(
    *,
    vuln_id: str = "CVE-2020-14343",
    scan_status: ScanStatus = ScanStatus.COMPLETED,
    sbom_status: SBOMCompletenessStatus = SBOMCompletenessStatus.COMPLETE,
    intel_conflict: bool = False,
    reach_state: ReachabilityState = ReachabilityState.REACHABLE,
    dep_status: DependencySymbolResolutionStatus = DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE,
    unresolved: bool = False,
    files_failed: int = 0,
    truncated: bool = False,
) -> DiscoveryResult:
    pkg = PackageRecord(
        package_id="pkg:pypi/PyYAML@5.4.1",
        name="PyYAML",
        version="5.4.1",
        ecosystem="pypi",
        purl="pkg:pypi/PyYAML@5.4.1",
    )
    vuln = VulnerabilityRecord(
        vulnerability_id=vuln_id,
        package_id=pkg.package_id,
        fixed_version="6.0",
        source="trivy",
    )
    intel = VulnerabilityIntelligenceReport(
        assessment_id="test-a1",
        intelligence_status=(
            IntelligenceStatus.PARTIALLY_ENRICHED
            if intel_conflict
            else IntelligenceStatus.ENRICHED
        ),
        conflicting_records=1 if intel_conflict else 0,
        vulnerabilities=[
            VulnerabilityIntelligence(
                vulnerability_id=vuln_id,
                canonical_id=vuln_id,
                aliases=["PYSEC-2021-142"],
                package_id=pkg.package_id,
                fixed_versions=["6.0"],
                overall_correlation=(
                    CorrelationOutcome.CONFLICTING_EVIDENCE
                    if intel_conflict
                    else CorrelationOutcome.EXACT_IDENTIFIER_MATCH
                ),
                overall_version_status=(
                    VersionMatchStatus.NOT_AFFECTED
                    if intel_conflict
                    else VersionMatchStatus.AFFECTED
                ),
                intelligence_status=IntelligenceStatus.ENRICHED,
            )
        ],
    )
    cand = CandidateVulnerableSymbol(
        module="yaml",
        qualified_name="yaml.load",
        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
        confidence=SymbolConfidence.VERIFIED,
    )
    u_calls = (
        [
            UnresolvedCall(
                caller="app.main",
                raw_expression="getattr(yaml, mode)",
                category="dynamic_attribute_lookup",
                reason="Dynamic getattr",
                location=CodeLocation(file="app.py", line=3),
            )
        ]
        if unresolved
        else []
    )
    reach = StaticReachabilityReport(
        files_discovered=1,
        files_parsed=1 if files_failed == 0 else 0,
        files_failed=files_failed,
        truncated=truncated,
        entry_points=[EntryPoint(qualified_name="app.main", module="app", source="python_main_block")],
        results=[
            ReachabilityResult(
                vulnerability_id=vuln_id,
                package_id=pkg.package_id,
                package_name="PyYAML",
                ecosystem="pypi",
                candidate_symbol=cand if reach_state != ReachabilityState.MISSING_CANDIDATE_SYMBOLS else None,
                dependency_symbol_status=dep_status,
                entry_point="app.main" if reach_state == ReachabilityState.REACHABLE else None,
                reachable=(
                    True
                    if reach_state == ReachabilityState.REACHABLE
                    else (False if reach_state == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET else None)
                ),
                state=reach_state,
                path=["app.main", "yaml.load"] if reach_state == ReachabilityState.REACHABLE else [],
                path_length=1 if reach_state == ReachabilityState.REACHABLE else None,
                unresolved_calls=u_calls,
            )
        ],
        unresolved_calls=u_calls,
    )
    return DiscoveryResult(
        assessment_id="test-a1",
        target=AssessmentTarget(target_path="."),
        scan_metadata=ScanMetadata(scan_status=scan_status),
        sbom=SBOMRecord(completeness_status=sbom_status, packages=[pkg.package_id]),
        packages=[pkg],
        vulnerabilities=[vuln],
        intelligence=intel,
        reachability=reach,
    )


@pytest.mark.unit
def test_openvex_statement_schema_invariants_and_validator() -> None:
    # not_affected without justification OR impact_statement must fail
    with pytest.raises(ValidationError, match="not_affected"):
        VEXStatement(
            vulnerability={"name": "CVE-2020-14343"},
            products=["pkg:pypi/PyYAML@5.4.1"],
            status=VEXStatus.NOT_AFFECTED,
        )

    # affected carrying justification must fail
    with pytest.raises(ValidationError, match="justification"):
        VEXStatement(
            vulnerability={"name": "CVE-2020-14343"},
            products=["pkg:pypi/PyYAML@5.4.1"],
            status=VEXStatus.AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        )

    ok_bad, errs = validate_openvex_json_payload(
        {
            "@context": "https://wrong.example",
            "@id": "",
            "timestamp": "not-iso",
            "version": 0,
            "statements": [{"vulnerability": {}, "products": [], "status": "bogus"}],
        }
    )
    assert not ok_bad
    assert len(errs) >= 4


@pytest.mark.unit
def test_deterministic_policy_fails_closed_against_gaps_and_conflicts() -> None:
    # 1. Reachable -> AFFECTED
    res_reach = evaluate_vex_policy(_base_discovery(reach_state=ReachabilityState.REACHABLE))
    assert res_reach.decisions[0].decided_status == VEXStatus.AFFECTED
    valid, errs = validate_openvex_document(res_reach.openvex_document)
    assert valid, errs

    # 2. Clean NO_PATH + verified dep AST + complete SBOM -> NOT_AFFECTED
    res_clean = evaluate_vex_policy(
        _base_discovery(
            reach_state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            dep_status=DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE,
        )
    )
    assert res_clean.decisions[0].decided_status == VEXStatus.NOT_AFFECTED
    assert (
        res_clean.decisions[0].justification
        == VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    )

    # 3. NO_PATH WITHOUT dependency AST verification -> MUST be UNDER_INVESTIGATION
    res_unverified_dep = evaluate_vex_policy(
        _base_discovery(
            reach_state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            dep_status=DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE,
        )
    )
    assert res_unverified_dep.decisions[0].decided_status == VEXStatus.UNDER_INVESTIGATION

    # 4. NO_PATH with INCOMPLETE SBOM -> MUST be UNDER_INVESTIGATION
    res_bad_sbom = evaluate_vex_policy(
        _base_discovery(
            reach_state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            sbom_status=SBOMCompletenessStatus.INCOMPLETE,
        )
    )
    assert res_bad_sbom.decisions[0].decided_status == VEXStatus.UNDER_INVESTIGATION

    # 5. Advisory conflict -> MUST be UNDER_INVESTIGATION
    res_conflict = evaluate_vex_policy(
        _base_discovery(
            reach_state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            intel_conflict=True,
        )
    )
    assert res_conflict.decisions[0].decided_status == VEXStatus.UNDER_INVESTIGATION

    # 6. Dynamic UNRESOLVED / ANALYSIS_INCOMPLETE / MISSING_CANDIDATE_SYMBOLS -> UNDER_INVESTIGATION
    for state in (
        ReachabilityState.UNRESOLVED,
        ReachabilityState.ANALYSIS_INCOMPLETE,
        ReachabilityState.MISSING_CANDIDATE_SYMBOLS,
    ):
        res_u = evaluate_vex_policy(_base_discovery(reach_state=state, unresolved=(state == ReachabilityState.UNRESOLVED)))
        assert res_u.decisions[0].decided_status == VEXStatus.UNDER_INVESTIGATION

    # 7. Runtime non-observation alone never triggers NOT_AFFECTED (empty runtime_observations={})
    res_rt_empty = evaluate_vex_policy(
        _base_discovery(
            reach_state=ReachabilityState.UNRESOLVED,
        ),
        runtime_observations={},
    )
    assert res_rt_empty.decisions[0].decided_status == VEXStatus.UNDER_INVESTIGATION
