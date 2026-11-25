"""Attack Path Intelligence Engine package (Milestone 4)."""

from packages.core.engines.attack_path.orchestrator import AttackPathOrchestrator
from packages.core.engines.attack_path.surface_classifier import (
    EntrySurfaceClassification,
    classify_entry_surface,
)
from packages.core.engines.attack_path.taint_tracer import (
    TaintTraceResult,
    trace_taint_along_path,
)

__all__ = [
    "AttackPathOrchestrator",
    "EntrySurfaceClassification",
    "TaintTraceResult",
    "classify_entry_surface",
    "trace_taint_along_path",
]
