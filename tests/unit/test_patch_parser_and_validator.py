"""Unit tests for upstream patch fetching/parsing and deterministic symbol validation."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from packages.core.analysis.python.dependency_symbols import DependencySymbolResolver
from packages.core.config.settings import Settings
from packages.core.engines.ai_intelligence.llm_provider import LLMProposedSymbol
from packages.core.engines.ai_intelligence.patch_fetcher import (
    PatchFetcher,
    normalize_patch_url,
)
from packages.core.engines.ai_intelligence.patch_parser import (
    compare_python_ast_versions,
    extract_patch_record,
)
from packages.core.engines.ai_intelligence.validator import CandidateSymbolValidator
from packages.core.models.ai_intelligence import PatchFetchStatus
from packages.core.models.reachability import SymbolConfidence, SymbolSource

AI_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "ai_intelligence"
FAKE_REQUESTS_DEP = AI_FIXTURES / "fake_requests_dep"


@pytest.mark.unit
def test_patch_fetcher_ssrf_allowlist_redirects_and_bounds() -> None:
    assert (
        normalize_patch_url("https://github.com/psf/requests/commit/74ea7cf7")
        == "https://github.com/psf/requests/commit/74ea7cf7.diff"
    )
    assert (
        normalize_patch_url("https://github.com/psf/requests/pull/6449")
        == "https://github.com/psf/requests/pull/6449.diff"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("redirect_ssrf.diff"):
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
        if url.endswith("oversized.diff"):
            return httpx.Response(200, content=b"+" * 5000)
        return httpx.Response(200, text="diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n")

    settings = Settings(patch_max_bytes=2048)
    fetcher = PatchFetcher(
        settings=settings,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    # Blocked HTTP, metadata IP, and unapproved host
    assert fetcher.fetch_url("http://github.com/psf/requests/commit/abc1234.diff").fetch_status == PatchFetchStatus.BLOCKED_UNTRUSTED_URL
    assert fetcher.fetch_url("https://169.254.169.254/latest").fetch_status == PatchFetchStatus.BLOCKED_UNTRUSTED_URL
    assert fetcher.fetch_url("https://evil.example/evil.diff").fetch_status == PatchFetchStatus.BLOCKED_UNTRUSTED_URL

    # Redirect to private IP must be blocked
    redir = fetcher.fetch_url("https://github.com/psf/requests/commit/redirect_ssrf.diff")
    assert redir.fetch_status == PatchFetchStatus.BLOCKED_UNTRUSTED_URL

    # Oversized payload blocked
    big = fetcher.fetch_url("https://github.com/psf/requests/commit/oversized.diff")
    assert big.fetch_status == PatchFetchStatus.SIZE_LIMIT_EXCEEDED

    # Valid GitHub diff fetched with SHA-256
    ok = fetcher.fetch_url("https://github.com/psf/requests/commit/74ea7cf7.diff")
    assert ok.fetch_status == PatchFetchStatus.RETRIEVED
    assert ok.patch_sha256 is not None and len(ok.patch_sha256) == 64


@pytest.mark.unit
def test_ast_version_comparator_and_diff_line_alignment() -> None:
    before = "class Session:\n    def request(self, url):\n        return url\n\ndef obsolete():\n    pass\n"
    after = "class Session:\n    def request(self, url):\n        return url.strip()\n\ndef added_guard():\n    return True\n"
    diffs = compare_python_ast_versions(
        file_path="src/requests/sessions.py",
        before_source=before,
        after_source=after,
    )
    by_q = {d.qualified_name: d for d in diffs}
    assert by_q["requests.sessions.Session.request"].change_type == "modified"
    assert by_q["requests.sessions.Session.request"].ast_verified_from_source is True
    assert by_q["requests.sessions.obsolete"].change_type == "deleted"
    assert by_q["requests.sessions.added_guard"].change_type == "added"

    # Also test diff alignment against fake_requests_dep without before/after snapshots
    diff_text = (AI_FIXTURES / "requests_patch.diff").read_text(encoding="utf-8")
    parsed_rec = extract_patch_record(
        vulnerability_id="CVE-2023-32681",
        source_ref="requests_patch.diff",
        diff_text=diff_text,
        fetch_status=PatchFetchStatus.LOCAL_FIXTURE,
        dependency_source_dirs=[FAKE_REQUESTS_DEP],
    )
    assert "requests/sessions.py" in parsed_rec.changed_files
    assert any(
        m.qualified_name == "requests.sessions.Session.request" and m.ast_verified_from_source
        for m in parsed_rec.modified_symbols
    )


@pytest.mark.unit
def test_deterministic_validator_blocks_hallucinated_and_cross_package_symbols() -> None:
    validator_with_ast = CandidateSymbolValidator(
        DependencySymbolResolver(dependency_source_dirs=[FAKE_REQUESTS_DEP])
    )
    diff_text = (AI_FIXTURES / "requests_patch.diff").read_text(encoding="utf-8")
    parsed = extract_patch_record(
        vulnerability_id="CVE-2023-32681",
        source_ref="requests_patch.diff",
        diff_text=diff_text,
        fetch_status=PatchFetchStatus.LOCAL_FIXTURE,
        dependency_source_dirs=[FAKE_REQUESTS_DEP],
    )

    llm_proposals = [
        # Real existing symbol in fake_requests_dep -> accepted HIGH (stays AI_ASSISTED_UNVERIFIED)
        LLMProposedSymbol(
            module="requests",
            qualified_name="requests.get",
            symbol_type="function",
            rationale="Public entry calling Session.request",
        ),
        # Hallucinated symbol absent from dependency AST -> rejected
        LLMProposedSymbol(
            module="requests.sessions",
            qualified_name="requests.sessions.Session.nonexistent_vuln_helper",
            symbol_type="method",
        ),
        # Cross-package hallucination -> rejected
        LLMProposedSymbol(
            module="os",
            qualified_name="os.system",
            symbol_type="function",
        ),
        # Injection string in identifier -> rejected
        LLMProposedSymbol(
            module="requests",
            qualified_name="requests.get(); eval('x')",
            symbol_type="function",
        ),
    ]

    result = validator_with_ast.validate_candidates(
        package_name="requests",
        declared_import_names=["requests"],
        patch_diffs=parsed.modified_symbols,
        llm_proposals=llm_proposals,
        patch_evidence_refs=["requests_patch.diff"],
        llm_provider_name="openai_compatible",
    )

    accepted_q = {c.qualified_name: c for c in result.accepted}
    assert "requests.sessions.Session.request" in accepted_q
    assert accepted_q["requests.sessions.Session.request"].source == SymbolSource.UPSTREAM_PATCH_DIFF
    assert accepted_q["requests.sessions.Session.request"].confidence == SymbolConfidence.VERIFIED

    assert "requests.get" in accepted_q
    assert accepted_q["requests.get"].source == SymbolSource.AI_ASSISTED_UNVERIFIED
    assert accepted_q["requests.get"].confidence == SymbolConfidence.HIGH
    assert accepted_q["requests.get"].evidence is not None
    assert accepted_q["requests.get"].evidence.verified_by_deterministic_check is True

    rejected_reasons = {r.qualified_name: r.reason for r in result.rejected}
    assert rejected_reasons["requests.sessions.Session.nonexistent_vuln_helper"] == "ABSENT_IN_DEPENDENCY_SOURCE_AST"
    assert "CROSS_PACKAGE" in rejected_reasons["os.system"]
    assert rejected_reasons["requests.get(); eval('x')"] == "INVALID_SYMBOL_IDENTIFIER_SYNTAX"

    # Without dependency source AST, LLM proposal MUST remain unverified (MEDIUM, det=False)
    validator_no_ast = CandidateSymbolValidator(DependencySymbolResolver())
    no_ast_res = validator_no_ast.validate_candidates(
        package_name="requests",
        declared_import_names=["requests"],
        llm_proposals=[llm_proposals[0]],
        llm_provider_name="openai_compatible",
    )
    cand = no_ast_res.accepted[0]
    assert cand.source == SymbolSource.AI_ASSISTED_UNVERIFIED
    assert cand.confidence == SymbolConfidence.MEDIUM
    assert cand.evidence is not None
    assert cand.evidence.verified_by_deterministic_check is False
