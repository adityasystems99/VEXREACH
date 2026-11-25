"""Unit tests for Phase 5 reachability and candidate symbol models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from packages.core.models.discovery import (
    AssessmentTarget,
    DiscoveryResult,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
    TargetType,
)
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    ReachabilityEvidence,
    ReachabilityResult,
    ReachabilityState,
    ReachabilityStatus,
    StaticReachabilityReport,
    SymbolConfidence,
    SymbolEvidence,
    SymbolPackageTarget,
    SymbolSource,
    VulnerabilitySymbolEntry,
    VulnerabilitySymbolManifest,
)


@pytest.mark.unit
def test_ai_assisted_symbol_cannot_claim_verified_without_deterministic_check() -> None:
    """Enforce non-negotiable guardrail: AI-suggested symbols cannot self-verify."""
    with pytest.raises(ValidationError, match="AI-assisted"):
        CandidateVulnerableSymbol(
            module="yaml",
            qualified_name="yaml.load",
            source=SymbolSource.AI_ASSISTED_UNVERIFIED,
            confidence=SymbolConfidence.VERIFIED,
        )

    # Allowed when explicitly marked as deterministically verified
    allowed = CandidateVulnerableSymbol(
        module="yaml",
        qualified_name="yaml.load",
        source=SymbolSource.AI_ASSISTED_UNVERIFIED,
        confidence=SymbolConfidence.VERIFIED,
        evidence=SymbolEvidence(
            source=SymbolSource.AI_ASSISTED_UNVERIFIED,
            confidence=SymbolConfidence.VERIFIED,
            verified_by_deterministic_check=True,
        ),
    )
    assert allowed.evidence is not None
    assert allowed.evidence.verified_by_deterministic_check is True


@pytest.mark.unit
def test_manifest_validation_and_state_counts() -> None:
    """Verify manifest roundtrip and StaticReachabilityReport state_counts aggregation."""
    manifest = VulnerabilitySymbolManifest(
        entries=[
            VulnerabilitySymbolEntry(
                vulnerability_id="CVE-2020-14343",
                package=SymbolPackageTarget(ecosystem="pypi", name="PyYAML", import_names=["yaml"]),
                symbols=[
                    CandidateVulnerableSymbol(
                        module="yaml",
                        qualified_name="yaml.load",
                        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
                        confidence=SymbolConfidence.VERIFIED,
                    )
                ],
            )
        ]
    )
    restored = VulnerabilitySymbolManifest.model_validate_json(manifest.model_dump_json())
    assert restored.entries[0].symbols[0].qualified_name == "yaml.load"

    report = StaticReachabilityReport(
        results=[
            ReachabilityResult(
                vulnerability_id="CVE-1",
                package_name="PyYAML",
                ecosystem="pypi",
                reachable=True,
                state=ReachabilityState.REACHABLE,
            ),
            ReachabilityResult(
                vulnerability_id="CVE-2",
                package_name="urllib3",
                ecosystem="pypi",
                reachable=False,
                state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            ),
            ReachabilityResult(
                vulnerability_id="CVE-3",
                package_name="requests",
                ecosystem="pypi",
                reachable=None,
                state=ReachabilityState.UNRESOLVED,
                dependency_symbol_status=DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE,
            ),
        ]
    )
    counts = report.state_counts()
    assert counts["reachable"] == 1
    assert counts["no_path_within_supported_subset"] == 1
    assert counts["unresolved"] == 1
    assert counts["missing_candidate_symbols"] == 0


@pytest.mark.unit
def test_legacy_reachability_models_remain_compatible() -> None:
    """Ensure Phase 2 reachability placeholders continue working alongside Phase 5 models."""
    ev = ReachabilityEvidence(
        status=ReachabilityStatus.DYNAMIC_UNCERTAINTY,
        target_symbol="yaml.load",
    )
    assert ev.status == ReachabilityStatus.DYNAMIC_UNCERTAINTY

    discovery = DiscoveryResult(
        target=AssessmentTarget(
            target_path=".",
            target_type=TargetType.REPOSITORY,
        ),
        scan_metadata=ScanMetadata(scan_status=ScanStatus.COMPLETED),
        sbom=SBOMRecord(),
        reachability=StaticReachabilityReport(),
    )
    assert discovery.reachability is not None
    assert discovery.reachability.language == "python"
