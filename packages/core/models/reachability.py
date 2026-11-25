"""Canonical Pydantic domain models for static reachability, symbol manifests, and call graphs."""

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import Field, model_validator

from packages.core.models.base import VEXReachBaseModel


class ReachabilityStatus(str, Enum):
    """Legacy Phase 2 categorical reachability state (preserved for backward compatibility)."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    DYNAMIC_UNCERTAINTY = "dynamic_uncertainty"
    UNSUPPORTED = "unsupported"


class ReachabilityEvidence(VEXReachBaseModel):
    """Legacy Phase 2 reachability summary model (preserved for backward compatibility)."""

    status: ReachabilityStatus
    target_symbol: str = Field(..., description="Full symbol name evaluated")
    call_paths: list[list[str]] = Field(
        default_factory=list,
        description="List of paths from entry points to the target symbol",
    )
    unresolved_dynamic_calls: list[str] = Field(
        default_factory=list,
        description="Locations where dynamic dispatch (getattr/eval) prevents deterministic traversal",
    )
    entry_points_evaluated: list[str] = Field(
        default_factory=list,
        description="Application ingress functions analyzed as roots",
    )
    graph_node_count: int = Field(default=0, description="Total nodes in the parsed application call graph")
    graph_edge_count: int = Field(default=0, description="Total directed edges in the call graph")


# ---------------------------------------------------------------------------
# Phase 5: Candidate Vulnerable Symbol Manifest Models
# ---------------------------------------------------------------------------


class SymbolSource(str, Enum):
    """Origin of a candidate vulnerable symbol assertion."""

    CURATED_ADVISORY_ANALYSIS = "curated_advisory_analysis"
    UPSTREAM_PATCH_DIFF = "upstream_patch_diff"
    MAINTAINER_VEX = "maintainer_vex"
    AI_ASSISTED_UNVERIFIED = "ai_assisted_unverified"
    USER_DECLARED = "user_declared"
    OTHER = "other"


class SymbolConfidence(str, Enum):
    """Confidence tier of a candidate vulnerable symbol."""

    VERIFIED = "verified"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class SymbolEvidence(VEXReachBaseModel):
    """Provenance record backing a candidate vulnerable symbol."""

    source: SymbolSource
    evidence_reference: str | None = Field(default=None)
    confidence: SymbolConfidence = Field(default=SymbolConfidence.UNVERIFIED)
    notes: str = Field(default="")
    verified_by_deterministic_check: bool = Field(default=False)


class SymbolPackageTarget(VEXReachBaseModel):
    """Package identity associated with a vulnerability symbol manifest entry."""

    ecosystem: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    version: str | None = Field(default=None)
    purl: str | None = Field(default=None)
    import_names: list[str] = Field(default_factory=list)


class CandidateVulnerableSymbol(VEXReachBaseModel):
    """A single candidate vulnerable symbol targeted by static reachability analysis."""

    module: str = Field(..., min_length=1)
    qualified_name: str = Field(..., min_length=1)
    symbol_type: Literal["function", "method", "class", "attribute"] = "function"
    source: SymbolSource
    evidence_reference: str | None = Field(default=None)
    confidence: SymbolConfidence = Field(default=SymbolConfidence.UNVERIFIED)
    evidence: SymbolEvidence | None = Field(default=None)

    @model_validator(mode="after")
    def _enforce_ai_safety_and_populate_evidence(self) -> "CandidateVulnerableSymbol":
        """Ensure AI-generated symbols cannot auto-promote to VERIFIED without deterministic proof."""
        verified_det = (
            self.evidence.verified_by_deterministic_check if self.evidence is not None else False
        )
        if (
            self.source == SymbolSource.AI_ASSISTED_UNVERIFIED
            and self.confidence == SymbolConfidence.VERIFIED
            and not verified_det
        ):
            raise ValueError(
                "AI-assisted candidate symbols cannot be assigned 'verified' confidence "
                "without deterministic verification."
            )

        if self.evidence is None:
            self.evidence = SymbolEvidence(
                source=self.source,
                evidence_reference=self.evidence_reference,
                confidence=self.confidence,
                verified_by_deterministic_check=verified_det,
            )
        return self


class VulnerabilitySymbolEntry(VEXReachBaseModel):
    """Mapping from a vulnerability & package to zero or more candidate vulnerable symbols."""

    vulnerability_id: str = Field(..., min_length=1)
    package: SymbolPackageTarget
    symbols: list[CandidateVulnerableSymbol] = Field(default_factory=list)


class VulnerabilitySymbolManifest(VEXReachBaseModel):
    """Validated collection of candidate vulnerable symbol mappings."""

    manifest_version: str = Field(default="1.0", min_length=1)
    entries: list[VulnerabilitySymbolEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 5: Python Static Call Graph & Reachability Models
# ---------------------------------------------------------------------------


class ReachabilityState(str, Enum):
    """Explicit static reachability outcomes preserving scope and uncertainty."""

    REACHABLE = "reachable"
    NO_PATH_WITHIN_SUPPORTED_SUBSET = "no_path_within_supported_subset"
    UNRESOLVED = "unresolved"
    ANALYSIS_INCOMPLETE = "analysis_incomplete"
    MISSING_CANDIDATE_SYMBOLS = "missing_candidate_symbols"
    TARGET_SYMBOL_NOT_FOUND = "target_symbol_not_found"


class DependencySymbolResolutionStatus(str, Enum):
    """Resolution status of a candidate vulnerable symbol in dependency metadata/sources."""

    VERIFIED_IN_DEPENDENCY_SOURCE = "verified_in_dependency_source"
    NOT_FOUND_IN_DEPENDENCY_SOURCE = "not_found_in_dependency_source"
    DEPENDENCY_SOURCE_UNAVAILABLE = "dependency_source_unavailable"
    IMPORT_MAPPING_AMBIGUOUS = "import_mapping_ambiguous"
    UNSUPPORTED_SYMBOL_STRUCTURE = "unsupported_symbol_structure"


class CodeLocation(VEXReachBaseModel):
    """Portable repository-relative source code location."""

    file: str = Field(..., min_length=1, description="Repository-relative POSIX path")
    line: int = Field(..., ge=1)
    column: int = Field(default=0, ge=0)
    end_line: int | None = Field(default=None, ge=1)


class EntryPointRule(VEXReachBaseModel):
    """User-declared entry point configuration item."""

    module: str = Field(..., min_length=1)
    qualified_name: str = Field(..., min_length=1)
    source: str = Field(default="user_config", min_length=1)


class EntryPointConfig(VEXReachBaseModel):
    """Validated explicit entry-point configuration file model."""

    entry_points: list[EntryPointRule] = Field(default_factory=list)


class EntryPoint(VEXReachBaseModel):
    """Identified application entry point used as a traversal root."""

    qualified_name: str = Field(..., min_length=1)
    module: str = Field(..., min_length=1)
    source: str = Field(..., min_length=1, description="user_config, python_main_block, fastapi_route, etc.")
    confidence: Literal["verified", "candidate", "unresolved"] = "verified"
    location: CodeLocation | None = Field(default=None)
    metadata: dict[str, str] = Field(default_factory=dict)


class CallGraphNode(VEXReachBaseModel):
    """Callable node within the constructed static call graph."""

    node_id: str = Field(..., min_length=1)
    module: str = Field(..., min_length=1)
    qualified_name: str = Field(..., min_length=1)
    node_type: Literal[
        "function",
        "async_function",
        "method",
        "class",
        "main_block",
        "external_symbol",
    ]
    is_external: bool = Field(default=False)
    is_entry_point: bool = Field(default=False)
    location: CodeLocation | None = Field(default=None)
    decorators: list[str] = Field(default_factory=list)


class CallGraphEdge(VEXReachBaseModel):
    """Directed call edge with provenance and all observed source call sites."""

    caller: str = Field(..., min_length=1)
    callee: str = Field(..., min_length=1)
    resolution_method: str = Field(..., min_length=1)
    source_locations: list[CodeLocation] = Field(default_factory=list)


class UnresolvedCall(VEXReachBaseModel):
    """Call expression or dynamic dispatch construct that could not be statically resolved."""

    caller: str = Field(..., min_length=1)
    raw_expression: str = Field(..., min_length=1)
    category: str = Field(
        ...,
        min_length=1,
        description="e.g., dynamic_attribute_lookup, dynamic_import, eval_exec, ambiguous_receiver",
    )
    reason: str = Field(..., min_length=1)
    location: CodeLocation


class AnalysisDiagnostic(VEXReachBaseModel):
    """Structured diagnostic explaining analysis limitations, errors, or truncation."""

    code: str = Field(..., min_length=1)
    severity: Literal["info", "warning", "error"] = "warning"
    message: str = Field(..., min_length=1)
    location: CodeLocation | None = Field(default=None)
    construct_kind: str | None = Field(default=None)
    affected_scope: str | None = Field(default=None)


class ReachabilityPath(VEXReachBaseModel):
    """Concrete static call path from an entry point to a target symbol with supporting edges."""

    entry_point: str = Field(..., min_length=1)
    target_symbol: str = Field(..., min_length=1)
    nodes: list[str] = Field(..., min_length=2)
    path_length: int = Field(..., ge=1)
    supporting_edges: list[CallGraphEdge] = Field(default_factory=list)


class ReachabilityResult(VEXReachBaseModel):
    """Per-(vulnerability, package, candidate symbol) static reachability assessment."""

    vulnerability_id: str = Field(..., min_length=1)
    package_id: str | None = Field(default=None)
    package_name: str = Field(..., min_length=1)
    ecosystem: str = Field(..., min_length=1)
    candidate_symbol: CandidateVulnerableSymbol | None = Field(default=None)
    dependency_symbol_status: DependencySymbolResolutionStatus = Field(
        default=DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE
    )
    entry_point: str | None = Field(default=None)
    reachable: bool | None = Field(
        default=None,
        description="True if static path found, False if none in supported subset, None if unresolved/incomplete/missing",
    )
    state: ReachabilityState
    path: list[str] = Field(default_factory=list)
    paths: list[ReachabilityPath] = Field(default_factory=list)
    path_length: int | None = Field(default=None, ge=1)
    supporting_edges: list[CallGraphEdge] = Field(default_factory=list)
    unresolved_calls: list[UnresolvedCall] = Field(default_factory=list)
    analysis_scope: str = Field(default="python_ast_call_graph_v1")
    diagnostics: list[AnalysisDiagnostic] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)


class StaticReachabilityReport(VEXReachBaseModel):
    """Complete Python static reachability analysis output for a target repository."""

    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    analyzer_name: str = Field(default="vexreach-python-ast")
    analyzer_version: str = Field(default="0.1.0")
    language: str = Field(default="python")
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_snapshot_hash: str | None = Field(default=None)
    manifest_sha256: str | None = Field(default=None)
    files_discovered: int = Field(default=0, ge=0)
    files_parsed: int = Field(default=0, ge=0)
    files_failed: int = Field(default=0, ge=0)
    graph_node_count: int = Field(default=0, ge=0)
    graph_edge_count: int = Field(default=0, ge=0)
    max_graph_depth: int = Field(default=15, ge=1)
    max_call_paths: int = Field(default=50, ge=1)
    truncated: bool = Field(default=False)
    vulnerabilities_analyzed: int = Field(default=0, ge=0)
    candidate_symbols_evaluated: int = Field(default=0, ge=0)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    results: list[ReachabilityResult] = Field(default_factory=list)
    unresolved_calls: list[UnresolvedCall] = Field(default_factory=list)
    diagnostics: list[AnalysisDiagnostic] = Field(default_factory=list)
    supported_subset_notes: list[str] = Field(
        default_factory=lambda: [
            "Static Python AST call-graph analysis (def, async def, classes, methods, nested functions).",
            "Conservative resolution of absolute, relative, aliased, and module-qualified calls.",
            "Static reachability indicates a possible call path within the supported subset; it does NOT establish runtime execution or exploitability.",
        ]
    )

    def state_counts(self) -> dict[str, int]:
        """Return count of ReachabilityResults grouped by ReachabilityState."""
        counts: dict[str, int] = {state.value: 0 for state in ReachabilityState}
        for res in self.results:
            counts[res.state.value] += 1
        return counts
