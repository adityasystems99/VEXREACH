"""Unit tests for symbol manifest loading and dependency AST verification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.core.analysis.python.dependency_symbols import (
    DependencySymbolResolver,
    canonicalize_pypi_name,
    load_symbol_manifest,
)
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    SymbolConfidence,
    SymbolSource,
)

DEP_FIXTURES = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "reachability"
    / "fake_dep_sources"
)


@pytest.mark.unit
def test_canonicalize_and_manifest_formats(tmp_path: Path) -> None:
    assert canonicalize_pypi_name("PyYAML") == "pyyaml"
    assert canonicalize_pypi_name("scikit_learn.core") == "scikit-learn-core"

    single_entry = tmp_path / "single.json"
    single_entry.write_text(
        json.dumps(
            {
                "vulnerability_id": "CVE-2020-14343",
                "package": {"ecosystem": "pypi", "name": "PyYAML"},
                "symbols": [
                    {
                        "module": "yaml",
                        "qualified_name": "yaml.load",
                        "source": "curated_advisory_analysis",
                        "confidence": "verified",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest, sha = load_symbol_manifest(single_entry)
    assert len(sha) == 64
    assert len(manifest.entries) == 1
    assert manifest.entries[0].symbols[0].qualified_name == "yaml.load"

    # AI-assisted verified claim in JSON must be rejected at manifest load time
    bad_ai = tmp_path / "bad_ai.json"
    bad_ai.write_text(
        json.dumps(
            [
                {
                    "vulnerability_id": "CVE-2024-1111",
                    "package": {"ecosystem": "pypi", "name": "PyYAML"},
                    "symbols": [
                        {
                            "module": "yaml",
                            "qualified_name": "yaml.load",
                            "source": "ai_assisted_unverified",
                            "confidence": "verified",
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="AI-assisted"):
        load_symbol_manifest(bad_ai)


@pytest.mark.unit
def test_dependency_source_ast_verification_never_executes_and_reports_absent() -> None:
    cand_present = CandidateVulnerableSymbol(
        module="yaml",
        qualified_name="yaml.load",
        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
        confidence=SymbolConfidence.VERIFIED,
    )
    cand_missing = CandidateVulnerableSymbol(
        module="yaml",
        qualified_name="yaml.nonexistent_api",
        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
        confidence=SymbolConfidence.HIGH,
    )

    # Without dependency source dir -> DEPENDENCY_SOURCE_UNAVAILABLE
    no_src = DependencySymbolResolver()
    check_unavailable = no_src.verify_symbol(package_name="PyYAML", candidate=cand_present)
    assert check_unavailable.status == DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE
    assert check_unavailable.candidate_graph_targets == ["yaml.load"]

    # With fake_dep_sources (contains `raise RuntimeError` at module top level!):
    # must succeed safely via AST without executing the file!
    with_src = DependencySymbolResolver(dependency_source_dirs=[DEP_FIXTURES])
    check_ok = with_src.verify_symbol(package_name="PyYAML", candidate=cand_present)
    assert check_ok.status == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE

    check_absent = with_src.verify_symbol(package_name="PyYAML", candidate=cand_missing)
    assert check_absent.status == DependencySymbolResolutionStatus.NOT_FOUND_IN_DEPENDENCY_SOURCE

    # Bad candidate structure
    bad_sym = CandidateVulnerableSymbol(
        module="yaml",
        qualified_name="yaml.bad call()",
        source=SymbolSource.USER_DECLARED,
        confidence=SymbolConfidence.LOW,
    )
    check_bad = with_src.verify_symbol(package_name="PyYAML", candidate=bad_sym)
    assert check_bad.status == DependencySymbolResolutionStatus.UNSUPPORTED_SYMBOL_STRUCTURE
