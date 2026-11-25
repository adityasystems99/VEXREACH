"""Orchestrator for AI Security Intelligence, patch parsing, and deterministic symbol validation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from packages.core.analysis.python.dependency_symbols import DependencySymbolResolver
from packages.core.config.settings import Settings, get_settings
from packages.core.engines.ai_intelligence.llm_provider import (
    LLMAnalysisRequest,
    LLMProvider,
    build_llm_provider,
)
from packages.core.engines.ai_intelligence.patch_fetcher import (
    PatchFetcher,
    PatchFetchResult,
)
from packages.core.engines.ai_intelligence.patch_parser import extract_patch_record
from packages.core.engines.ai_intelligence.sanitizer import PromptSanitizer
from packages.core.engines.ai_intelligence.validator import CandidateSymbolValidator
from packages.core.models.ai_intelligence import (
    AIAdvisoryIntelligenceReport,
    AIAdvisoryVulnerabilityAnalysis,
    ParsedPatchRecord,
    PatchFetchStatus,
    PromptInjectionSignal,
)
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.reachability import (
    SymbolPackageTarget,
    VulnerabilitySymbolEntry,
    VulnerabilitySymbolManifest,
)
from packages.core.utils.logging import get_logger

logger = get_logger("ai_intelligence.orchestrator")

_SYMBOL_MENTION_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){1,5})\b")


def extract_advisory_symbol_hints(
    advisory_text: str, allowed_roots: list[str]
) -> list[tuple[str, str]]:
    """Extract dotted Python symbol references matching known package import roots."""
    if not advisory_text or not allowed_roots:
        return []
    roots = set(allowed_roots)
    seen: set[str] = set()
    hints: list[tuple[str, str]] = []
    for match in _SYMBOL_MENTION_RE.finditer(advisory_text):
        qname = match.group(1)
        parts = qname.split(".")
        if parts[0] not in roots:
            continue
        # Ignore common filename extensions mistaken for attributes
        if parts[-1].lower() in {"py", "json", "txt", "yml", "yaml", "md", "rst", "whl"}:
            continue
        if qname not in seen:
            seen.add(qname)
            hints.append((".".join(parts[:-1]), qname))
    return hints


class AISecurityIntelligenceOrchestrator:
    """Extracts and validates candidate vulnerable symbols from advisories and upstream patches."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        llm_provider: LLMProvider | None = None,
        patch_fetcher: PatchFetcher | None = None,
        sanitizer: PromptSanitizer | None = None,
        dependency_source_dirs: list[Path] | None = None,
        explicit_package_map: dict[str, list[str]] | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._owns_llm = llm_provider is None
        self._llm = llm_provider or build_llm_provider(self._settings)
        self._owns_fetcher = patch_fetcher is None
        self._fetcher = patch_fetcher or PatchFetcher(settings=self._settings)
        self._sanitizer = sanitizer or PromptSanitizer()
        self._dependency_source_dirs = dependency_source_dirs or []
        self._dep_resolver = DependencySymbolResolver(
            dependency_source_dirs=self._dependency_source_dirs,
            explicit_package_map=explicit_package_map,
        )
        self._validator = CandidateSymbolValidator(self._dep_resolver)

    def __enter__(self) -> "AISecurityIntelligenceOrchestrator":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_fetcher:
            self._fetcher.close()
        if self._owns_llm:
            self._llm.close()

    def analyze_discovery_result(
        self,
        discovery_result: DiscoveryResult,
        *,
        local_patches_by_vuln: dict[str, list[Path]] | None = None,
        patch_dir: Path | None = None,
        before_after_sources_by_vuln: dict[str, dict[str, tuple[str | None, str | None]]] | None = None,
        fetch_remote_patches: bool = False,
    ) -> tuple[DiscoveryResult, AIAdvisoryIntelligenceReport, list[dict[str, Any]]]:
        """Run AI + patch intelligence across discovered Python vulnerabilities.

        Returns:
            `(updated_discovery_result, report, raw_patch_evidence_records)`
        """
        pkg_by_id = {pkg.package_id: pkg for pkg in discovery_result.packages}
        intel_by_vid = (
            {v.vulnerability_id: v for v in discovery_result.intelligence.vulnerabilities}
            if discovery_result.intelligence is not None
            else {}
        )

        analyses: list[AIAdvisoryVulnerabilityAnalysis] = []
        manifest_entries: list[VulnerabilitySymbolEntry] = []
        raw_patch_payloads: list[dict[str, Any]] = []
        warnings: list[str] = []

        total_patches = 0
        total_accepted = 0
        total_rejected = 0
        total_injections = 0

        for vuln in discovery_result.vulnerabilities:
            pkg = pkg_by_id.get(vuln.package_id)
            ecosystem = (pkg.ecosystem if pkg else "unknown").lower()
            pkg_name = pkg.name if pkg else vuln.package_id
            if ecosystem not in {"pypi", "python"}:
                continue

            intel = intel_by_vid.get(vuln.vulnerability_id)
            references = list(vuln.references)
            advisory_chunks = [vuln.title or "", vuln.description or ""]
            if intel is not None:
                for adv in intel.advisories:
                    advisory_chunks.append(adv.summary)
                    advisory_chunks.append(adv.details)
                    for ref in adv.references:
                        if ref.url not in references:
                            references.append(ref.url)
            advisory_text = "\n".join(c for c in advisory_chunks if c.strip())

            # Collect patch diffs (local fixtures/files + optional allowlisted remote patches)
            patch_results: list[PatchFetchResult] = []
            candidate_local_files: list[Path] = list((local_patches_by_vuln or {}).get(vuln.vulnerability_id, []))
            if patch_dir is not None and patch_dir.is_dir():
                for ext in (".diff", ".patch"):
                    matched_path = patch_dir / f"{vuln.vulnerability_id}{ext}"
                    if matched_path.is_file() and matched_path not in candidate_local_files:
                        candidate_local_files.append(matched_path)
                    if intel is not None:
                        for alias in intel.aliases:
                            alias_path = patch_dir / f"{alias}{ext}"
                            if alias_path.is_file() and alias_path not in candidate_local_files:
                                candidate_local_files.append(alias_path)

            for lp in candidate_local_files:
                patch_results.append(self._fetcher.load_local_patch(lp))

            if fetch_remote_patches:
                for patch_url in self._fetcher.extract_candidate_urls(references):
                    patch_results.append(self._fetcher.fetch_url(patch_url))

            parsed_patches: list[ParsedPatchRecord] = []
            all_modified_diffs = []
            combined_diff_parts: list[str] = []
            patch_evidence_refs: list[str] = []
            vuln_warnings: list[str] = []

            before_after = (before_after_sources_by_vuln or {}).get(vuln.vulnerability_id)

            for p_res in patch_results:
                if p_res.warning:
                    vuln_warnings.append(p_res.warning)
                raw_patch_payloads.append(
                    {
                        "vulnerability_id": vuln.vulnerability_id,
                        "source_ref": p_res.source_ref,
                        "fetch_status": p_res.fetch_status.value,
                        "patch_sha256": p_res.patch_sha256,
                        "warning": p_res.warning,
                    }
                )
                if p_res.patch_text is None:
                    parsed_patches.append(
                        ParsedPatchRecord(
                            vulnerability_id=vuln.vulnerability_id,
                            source_ref=p_res.source_ref,
                            fetch_status=p_res.fetch_status,
                            warnings=[p_res.warning] if p_res.warning else [],
                        )
                    )
                    continue

                total_patches += 1
                patch_evidence_refs.append(p_res.source_ref)
                parsed = extract_patch_record(
                    vulnerability_id=vuln.vulnerability_id,
                    source_ref=p_res.source_ref,
                    diff_text=p_res.patch_text,
                    fetch_status=p_res.fetch_status,
                    patch_sha256=p_res.patch_sha256,
                    before_after_sources=before_after,
                    dependency_source_dirs=self._dependency_source_dirs,
                )
                parsed_patches.append(parsed)
                all_modified_diffs.extend(parsed.modified_symbols)
                combined_diff_parts.append(parsed.diff_excerpt)
                vuln_warnings.extend(parsed.warnings)

            # Even if only before_after_sources were supplied without diff text
            if before_after and not patch_results:
                parsed = extract_patch_record(
                    vulnerability_id=vuln.vulnerability_id,
                    source_ref="in_memory_ast_snapshot",
                    diff_text="",
                    fetch_status=PatchFetchStatus.LOCAL_FIXTURE,
                    before_after_sources=before_after,
                    dependency_source_dirs=self._dependency_source_dirs,
                )
                parsed_patches.append(parsed)
                all_modified_diffs.extend(parsed.modified_symbols)

            # Quarantine untrusted advisory + diff text before sending to LLM
            diff_text_combined = "\n".join(combined_diff_parts)
            sys_prompt, user_prompt, injection_signals = (
                self._sanitizer.build_quarantined_prompt(
                    vulnerability_id=vuln.vulnerability_id,
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                    advisory_text=advisory_text,
                    diff_excerpt=diff_text_combined,
                )
            )
            if injection_signals:
                vuln_warnings.append(
                    f"Detected {len(injection_signals)} prompt-injection pattern(s) in untrusted advisory/patch content."
                )

            llm_resp = self._llm.analyze_structured(
                LLMAnalysisRequest(
                    vulnerability_id=vuln.vulnerability_id,
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                    system_prompt=sys_prompt,
                    user_prompt=user_prompt,
                )
            )
            vuln_warnings.extend(llm_resp.warnings)

            import_roots = self._dep_resolver.resolve_import_roots(pkg_name)
            advisory_hints = extract_advisory_symbol_hints(advisory_text, import_roots)

            val_result = self._validator.validate_candidates(
                package_name=pkg_name,
                declared_import_names=import_roots,
                patch_diffs=all_modified_diffs,
                llm_proposals=llm_resp.proposed_symbols,
                advisory_hints=advisory_hints,
                patch_evidence_refs=patch_evidence_refs or references[:1],
                llm_provider_name=llm_resp.provider_name,
            )
            vuln_warnings.extend(val_result.warnings)

            confidence_notes: list[str] = []
            if any(
                s.evidence and s.evidence.verified_by_deterministic_check
                for s in val_result.accepted
            ):
                confidence_notes.append(
                    "One or more candidate symbols verified deterministically against dependency/patch AST."
                )
            elif val_result.accepted:
                confidence_notes.append(
                    "Candidate symbols have not yet been verified against installed dependency source AST."
                )

            total_accepted += len(val_result.accepted)
            total_rejected += len(val_result.rejected)
            total_injections += len(injection_signals)

            analyses.append(
                AIAdvisoryVulnerabilityAnalysis(
                    vulnerability_id=vuln.vulnerability_id,
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                    mechanism_summary=llm_resp.mechanism_summary,
                    affected_component_hint=llm_resp.affected_component_hint,
                    patch_records=parsed_patches,
                    accepted_symbols=val_result.accepted,
                    rejected_symbols=val_result.rejected,
                    prompt_injection_signals=injection_signals,
                    llm_provider_used=llm_resp.provider_name,
                    llm_model_used=llm_resp.model_name,
                    confidence_notes=confidence_notes,
                    warnings=vuln_warnings,
                )
            )
            manifest_entries.append(
                VulnerabilitySymbolEntry(
                    vulnerability_id=vuln.vulnerability_id,
                    package=SymbolPackageTarget(
                        ecosystem=ecosystem,
                        name=pkg_name,
                        version=pkg.version if pkg else None,
                        purl=pkg.purl if pkg else None,
                        import_names=import_roots,
                    ),
                    symbols=val_result.accepted,
                )
            )

        generated_manifest = VulnerabilitySymbolManifest(entries=manifest_entries)
        report = AIAdvisoryIntelligenceReport(
            llm_provider=self._llm.provider_name,
            llm_model=self._llm.model_name,
            vulnerabilities_processed=len(analyses),
            patches_retrieved=total_patches,
            candidates_accepted=total_accepted,
            candidates_rejected=total_rejected,
            prompt_injections_detected=total_injections,
            analyses=analyses,
            generated_manifest=generated_manifest,
            warnings=warnings,
        )
        updated_discovery = discovery_result.model_copy(update={"ai_intelligence": report})
        logger.info(
            "AI Security Intelligence processed %d Python vulns: accepted=%d, rejected=%d, injections=%d",
            len(analyses),
            total_accepted,
            total_rejected,
            total_injections,
        )
        return updated_discovery, report, raw_patch_payloads
