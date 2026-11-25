"""Deterministic validation of AI-suggested and patch-extracted vulnerable symbols."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from packages.core.analysis.python.dependency_symbols import (
    DependencySymbolResolver,
    canonicalize_pypi_name,
)
from packages.core.engines.ai_intelligence.llm_provider import LLMProposedSymbol
from packages.core.models.ai_intelligence import (
    ModifiedSymbolDiff,
    RejectedSymbolCandidate,
)
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    SymbolConfidence,
    SymbolEvidence,
    SymbolSource,
)

_IDENT_PART_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_valid_dotted_python_name(value: str) -> bool:
    if not value:
        return False
    parts = value.split(".")
    return all(_IDENT_PART_RE.match(p) for p in parts)


@dataclass
class ValidationBatchResult:
    """Validated candidate symbols split into accepted and rejected records."""

    accepted: list[CandidateVulnerableSymbol] = field(default_factory=list)
    rejected: list[RejectedSymbolCandidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CandidateSymbolValidator:
    """Validates candidate vulnerable symbols against package identity and static ASTs."""

    def __init__(self, dependency_resolver: DependencySymbolResolver | None = None) -> None:
        self._dep_resolver = dependency_resolver or DependencySymbolResolver()

    def validate_candidates(
        self,
        *,
        package_name: str,
        declared_import_names: list[str] | None = None,
        patch_diffs: list[ModifiedSymbolDiff] | None = None,
        llm_proposals: list[LLMProposedSymbol] | None = None,
        advisory_hints: list[tuple[str, str]] | None = None,
        patch_evidence_refs: list[str] | None = None,
        llm_provider_name: str | None = None,
    ) -> ValidationBatchResult:
        """Deterministically validate and deduplicate patch, advisory, and LLM symbol proposals."""
        batch = ValidationBatchResult()
        allowed_roots = set(
            self._dep_resolver.resolve_import_roots(package_name, declared_import_names)
        )
        allowed_roots.add(canonicalize_pypi_name(package_name).replace("-", "_"))
        primary_ref = patch_evidence_refs[0] if patch_evidence_refs else None

        by_qname: dict[str, CandidateVulnerableSymbol] = {}

        # 1. Deterministic patch diff symbols (highest priority)
        for mod_diff in patch_diffs or []:
            cand, rej = self._validate_single(
                package_name=package_name,
                declared_import_names=declared_import_names,
                allowed_roots=allowed_roots,
                module=mod_diff.module_name,
                qualified_name=mod_diff.qualified_name,
                symbol_type=mod_diff.symbol_type,
                source=SymbolSource.UPSTREAM_PATCH_DIFF,
                evidence_ref=primary_ref,
                notes=(
                    f"Modified symbol in upstream patch '{mod_diff.file_path}' "
                    f"(change={mod_diff.change_type}, ast_verified={mod_diff.ast_verified_from_source})."
                ),
                ast_verified_hint=mod_diff.ast_verified_from_source,
                provider_name=None,
            )
            if rej is not None:
                batch.rejected.append(rej)
            elif cand is not None:
                self._merge_best(by_qname, cand)

        # 2. Untrusted LLM proposals (strictly validated; cannot self-verify)
        for prop in llm_proposals or []:
            cand, rej = self._validate_single(
                package_name=package_name,
                declared_import_names=declared_import_names,
                allowed_roots=allowed_roots,
                module=prop.module,
                qualified_name=prop.qualified_name,
                symbol_type=prop.symbol_type,
                source=SymbolSource.AI_ASSISTED_UNVERIFIED,
                evidence_ref=primary_ref,
                notes=prop.rationale or f"Proposed by {llm_provider_name or 'llm'}",
                ast_verified_hint=False,
                provider_name=llm_provider_name,
            )
            if rej is not None:
                batch.rejected.append(rej)
            elif cand is not None:
                self._merge_best(by_qname, cand)

        # 3. Deterministic advisory regex hints
        for mod_name, qname in advisory_hints or []:
            cand, rej = self._validate_single(
                package_name=package_name,
                declared_import_names=declared_import_names,
                allowed_roots=allowed_roots,
                module=mod_name,
                qualified_name=qname,
                symbol_type="function",
                source=SymbolSource.OTHER,
                evidence_ref=None,
                notes="Symbol mention extracted conservatively from advisory text.",
                ast_verified_hint=False,
                provider_name=None,
            )
            if rej is not None:
                batch.rejected.append(rej)
            elif cand is not None:
                self._merge_best(by_qname, cand)

        batch.accepted = [by_qname[k] for k in sorted(by_qname)]
        return batch

    def _validate_single(
        self,
        *,
        package_name: str,
        declared_import_names: list[str] | None,
        allowed_roots: set[str],
        module: str,
        qualified_name: str,
        symbol_type: str,
        source: SymbolSource,
        evidence_ref: str | None,
        notes: str,
        ast_verified_hint: bool,
        provider_name: str | None,
    ) -> tuple[CandidateVulnerableSymbol | None, RejectedSymbolCandidate | None]:
        mod_clean = module.strip()
        qual_clean = qualified_name.strip()

        if not _is_valid_dotted_python_name(mod_clean) or not _is_valid_dotted_python_name(qual_clean):
            return None, RejectedSymbolCandidate(
                module=mod_clean or "<empty>",
                qualified_name=qual_clean or "<empty>",
                source=source,
                reason="INVALID_SYMBOL_IDENTIFIER_SYNTAX",
                provider=provider_name,
            )

        top_mod = mod_clean.split(".", 1)[0]
        top_qual = qual_clean.split(".", 1)[0]
        if top_mod not in allowed_roots or top_qual != top_mod:
            return None, RejectedSymbolCandidate(
                module=mod_clean,
                qualified_name=qual_clean,
                source=source,
                reason=(
                    f"CROSS_PACKAGE_OR_IMPORT_MISMATCH: '{top_qual}' not in expected "
                    f"import root(s) {sorted(allowed_roots)}"
                ),
                provider=provider_name,
            )

        # Build provisional unverified symbol to check against local dependency ASTs
        provisional = CandidateVulnerableSymbol(
            module=mod_clean,
            qualified_name=qual_clean,
            symbol_type=symbol_type,  # type: ignore[arg-type]
            source=source,
            evidence_reference=evidence_ref,
            confidence=SymbolConfidence.UNVERIFIED,
            evidence=SymbolEvidence(
                source=source,
                evidence_reference=evidence_ref,
                confidence=SymbolConfidence.UNVERIFIED,
                notes=notes,
                verified_by_deterministic_check=False,
            ),
        )

        dep_check = self._dep_resolver.verify_symbol(
            package_name=package_name,
            candidate=provisional,
            declared_import_names=declared_import_names or sorted(allowed_roots),
        )

        if dep_check.status == DependencySymbolResolutionStatus.NOT_FOUND_IN_DEPENDENCY_SOURCE:
            return None, RejectedSymbolCandidate(
                module=mod_clean,
                qualified_name=qual_clean,
                source=source,
                reason="ABSENT_IN_DEPENDENCY_SOURCE_AST",
                provider=provider_name,
            )

        if dep_check.status in {
            DependencySymbolResolutionStatus.UNSUPPORTED_SYMBOL_STRUCTURE,
            DependencySymbolResolutionStatus.IMPORT_MAPPING_AMBIGUOUS,
        }:
            return None, RejectedSymbolCandidate(
                module=mod_clean,
                qualified_name=qual_clean,
                source=source,
                reason=dep_check.status.value.upper(),
                provider=provider_name,
            )

        verified_in_ast = (
            dep_check.status == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE
        )

        if verified_in_ast:
            if source == SymbolSource.UPSTREAM_PATCH_DIFF:
                confidence = SymbolConfidence.VERIFIED
            else:
                confidence = SymbolConfidence.HIGH
            det_verified = True
        elif source == SymbolSource.UPSTREAM_PATCH_DIFF:
            confidence = SymbolConfidence.HIGH if ast_verified_hint else SymbolConfidence.MEDIUM
            det_verified = ast_verified_hint
        elif source == SymbolSource.AI_ASSISTED_UNVERIFIED:
            confidence = SymbolConfidence.MEDIUM
            det_verified = False
        else:
            confidence = SymbolConfidence.LOW
            det_verified = False

        accepted = CandidateVulnerableSymbol(
            module=mod_clean,
            qualified_name=qual_clean,
            symbol_type=symbol_type,  # type: ignore[arg-type]
            source=source,
            evidence_reference=evidence_ref,
            confidence=confidence,
            evidence=SymbolEvidence(
                source=source,
                evidence_reference=evidence_ref,
                confidence=confidence,
                notes=notes,
                verified_by_deterministic_check=det_verified,
            ),
        )
        return accepted, None

    @staticmethod
    def _merge_best(
        target: dict[str, CandidateVulnerableSymbol],
        candidate: CandidateVulnerableSymbol,
    ) -> None:
        rank = {
            SymbolConfidence.VERIFIED: 5,
            SymbolConfidence.HIGH: 4,
            SymbolConfidence.MEDIUM: 3,
            SymbolConfidence.LOW: 2,
            SymbolConfidence.UNVERIFIED: 1,
        }
        source_priority = {
            SymbolSource.UPSTREAM_PATCH_DIFF: 4,
            SymbolSource.CURATED_ADVISORY_ANALYSIS: 3,
            SymbolSource.AI_ASSISTED_UNVERIFIED: 2,
            SymbolSource.OTHER: 1,
        }
        existing = target.get(candidate.qualified_name)
        if existing is None:
            target[candidate.qualified_name] = candidate
            return
        new_score = (
            rank[candidate.confidence],
            source_priority.get(candidate.source, 0),
        )
        old_score = (
            rank[existing.confidence],
            source_priority.get(existing.source, 0),
        )
        if new_score > old_score:
            target[candidate.qualified_name] = candidate
