"""Domain models for static and dynamic reachability evidence."""

from enum import Enum
from pydantic import Field
from packages.core.models.base import VEXReachBaseModel


class ReachabilityStatus(str, Enum):
    """Categorical reachability state of a vulnerable symbol."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    DYNAMIC_UNCERTAINTY = "dynamic_uncertainty"
    UNSUPPORTED = "unsupported"


class ReachabilityEvidence(VEXReachBaseModel):
    """Verifiable proof of static reachability, or lack thereof."""

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
