"""NetworkX-backed Python static call graph construction and bounded traversal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from packages.core.analysis.python.resolver import (
    RepositoryModuleIndex,
    ResolutionOutcome,
)
from packages.core.config.settings import Settings, get_settings
from packages.core.models.reachability import (
    AnalysisDiagnostic,
    CallGraphEdge,
    CallGraphNode,
    CodeLocation,
    EntryPoint,
    ReachabilityPath,
)


@dataclass
class PathSearchResult:
    """Result of bounded path enumeration between entry points and a target symbol."""

    paths: list[ReachabilityPath] = field(default_factory=list)
    supporting_edges: list[CallGraphEdge] = field(default_factory=list)
    truncated: bool = False
    depth_limit_exceeded: bool = False


class PythonCallGraph:
    """In-memory directed static call graph backed by ``networkx.DiGraph``."""

    def __init__(self, *, max_nodes: int = 50_000, max_edges: int = 200_000) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.nodes: dict[str, CallGraphNode] = {}
        self.edges: dict[tuple[str, str], CallGraphEdge] = {}
        self.diagnostics: list[AnalysisDiagnostic] = []
        self.truncated: bool = False
        self.max_nodes = max_nodes
        self.max_edges = max_edges

    def add_node(self, node: CallGraphNode) -> bool:
        """Add or update a node in the call graph while respecting node caps."""
        if node.node_id in self.nodes:
            existing = self.nodes[node.node_id]
            if node.is_entry_point and not existing.is_entry_point:
                updated = existing.model_copy(update={"is_entry_point": True})
                self.nodes[node.node_id] = updated
                self.graph.nodes[node.node_id]["is_entry_point"] = True
            return True

        if len(self.nodes) >= self.max_nodes:
            if not self.truncated:
                self.truncated = True
                self.diagnostics.append(
                    AnalysisDiagnostic(
                        code="CALL_GRAPH_NODE_LIMIT_EXCEEDED",
                        severity="warning",
                        message=(
                            f"Call graph node cap ({self.max_nodes}) reached; "
                            "graph was truncated."
                        ),
                        construct_kind="call_graph",
                    )
                )
            return False

        self.nodes[node.node_id] = node
        self.graph.add_node(
            node.node_id,
            module=node.module,
            qualified_name=node.qualified_name,
            node_type=node.node_type,
            is_external=node.is_external,
            is_entry_point=node.is_entry_point,
        )
        return True

    def add_edge(
        self,
        *,
        caller: str,
        callee: str,
        resolution_method: str,
        location: CodeLocation,
    ) -> bool:
        """Add or merge a directed call edge while respecting edge caps."""
        if caller not in self.nodes or callee not in self.nodes:
            return False

        key = (caller, callee)
        if key in self.edges:
            edge = self.edges[key]
            existing_locs = {
                (loc.file, loc.line, loc.column) for loc in edge.source_locations
            }
            if (location.file, location.line, location.column) not in existing_locs:
                edge.source_locations.append(location)
                edge.source_locations.sort(
                    key=lambda loc: (loc.file, loc.line, loc.column)
                )
            return True

        if len(self.edges) >= self.max_edges:
            if not self.truncated:
                self.truncated = True
                self.diagnostics.append(
                    AnalysisDiagnostic(
                        code="CALL_GRAPH_EDGE_LIMIT_EXCEEDED",
                        severity="warning",
                        message=(
                            f"Call graph edge cap ({self.max_edges}) reached; "
                            "graph was truncated."
                        ),
                        construct_kind="call_graph",
                    )
                )
            return False

        edge = CallGraphEdge(
            caller=caller,
            callee=callee,
            resolution_method=resolution_method,
            source_locations=[location],
        )
        self.edges[key] = edge
        self.graph.add_edge(caller, callee, resolution_method=resolution_method)
        return True

    def mark_entry_points(self, entry_points: list[EntryPoint]) -> None:
        """Annotate existing graph nodes matching resolved entry points."""
        for ep in entry_points:
            if ep.confidence == "unresolved":
                continue
            if ep.qualified_name in self.nodes:
                node = self.nodes[ep.qualified_name]
                if not node.is_entry_point:
                    self.nodes[ep.qualified_name] = node.model_copy(
                        update={"is_entry_point": True}
                    )
                    self.graph.nodes[ep.qualified_name]["is_entry_point"] = True

    def find_paths(
        self,
        entry_point_ids: list[str],
        target_symbol: str,
        *,
        max_depth: int,
        max_paths: int,
    ) -> PathSearchResult:
        """Enumerate bounded simple call paths from ``entry_point_ids`` to ``target_symbol``."""
        if target_symbol not in self.graph:
            return PathSearchResult()

        collected: list[ReachabilityPath] = []
        truncated = False
        depth_limit_exceeded = False

        for entry_id in sorted(set(entry_point_ids)):
            if entry_id not in self.graph or entry_id == target_symbol:
                continue

            if len(collected) >= max_paths:
                if nx.has_path(self.graph, entry_id, target_symbol):
                    truncated = True
                continue

            path_iter = nx.all_simple_paths(
                self.graph, source=entry_id, target=target_symbol, cutoff=max_depth
            )
            found_for_entry = 0
            for raw_path in path_iter:
                if len(collected) >= max_paths:
                    truncated = True
                    break
                supporting = [
                    self.edges[(raw_path[idx], raw_path[idx + 1])]
                    for idx in range(len(raw_path) - 1)
                ]
                collected.append(
                    ReachabilityPath(
                        entry_point=entry_id,
                        target_symbol=target_symbol,
                        nodes=list(raw_path),
                        path_length=len(raw_path) - 1,
                        supporting_edges=supporting,
                    )
                )
                found_for_entry += 1

            if found_for_entry == 0 and nx.has_path(self.graph, entry_id, target_symbol):
                depth_limit_exceeded = True

        collected.sort(key=lambda item: (item.path_length, tuple(item.nodes)))

        edge_map: dict[tuple[str, str], CallGraphEdge] = {}
        for rp in collected:
            for edge in rp.supporting_edges:
                edge_map[(edge.caller, edge.callee)] = edge
        supporting_edges = [edge_map[key] for key in sorted(edge_map)]

        return PathSearchResult(
            paths=collected,
            supporting_edges=supporting_edges,
            truncated=truncated,
            depth_limit_exceeded=depth_limit_exceeded,
        )

    def to_serializable_dict(self) -> dict[str, Any]:
        """Serialize the call graph deterministically for ``call-graph.json`` evidence."""
        sorted_nodes = [
            self.nodes[key].model_dump(mode="json") for key in sorted(self.nodes)
        ]
        sorted_edges = [
            self.edges[key].model_dump(mode="json") for key in sorted(self.edges)
        ]
        return {
            "node_count": len(sorted_nodes),
            "edge_count": len(sorted_edges),
            "truncated": self.truncated,
            "nodes": sorted_nodes,
            "edges": sorted_edges,
            "diagnostics": [d.model_dump(mode="json") for d in self.diagnostics],
        }


class PythonCallGraphBuilder:
    """Builds a :class:`PythonCallGraph` from indexed symbols and resolved calls."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def build(
        self,
        index: RepositoryModuleIndex,
        resolution: ResolutionOutcome,
    ) -> PythonCallGraph:
        """Construct the static call graph with bounded node and edge limits."""
        call_graph = PythonCallGraph(
            max_nodes=self._settings.max_graph_nodes,
            max_edges=self._settings.max_graph_edges,
        )

        # Register internal function/method/main-block nodes deterministically
        for fn_qual in sorted(index.functions):
            fn_sym = index.functions[fn_qual]
            call_graph.add_node(
                CallGraphNode(
                    node_id=fn_qual,
                    module=fn_sym.module_name,
                    qualified_name=fn_qual,
                    node_type=fn_sym.node_type,
                    is_external=False,
                    location=fn_sym.location,
                    decorators=[dec.raw_name for dec in fn_sym.decorators],
                )
            )

        # Sort resolved call records deterministically before inserting external nodes & edges
        sorted_calls = sorted(
            resolution.resolved_calls,
            key=lambda c: (
                c.caller,
                c.callee,
                c.location.file,
                c.location.line,
                c.location.column,
            ),
        )
        for record in sorted_calls:
            if record.callee not in call_graph.nodes:
                if record.callee in index.classes:
                    cls_sym = index.classes[record.callee]
                    call_graph.add_node(
                        CallGraphNode(
                            node_id=record.callee,
                            module=cls_sym.module_name,
                            qualified_name=record.callee,
                            node_type="class",
                            is_external=False,
                            location=cls_sym.location,
                            decorators=[dec.raw_name for dec in cls_sym.decorators],
                        )
                    )
                else:
                    ext_module = (
                        record.callee.rsplit(".", 1)[0]
                        if "." in record.callee
                        else record.callee
                    )
                    call_graph.add_node(
                        CallGraphNode(
                            node_id=record.callee,
                            module=ext_module,
                            qualified_name=record.callee,
                            node_type="external_symbol",
                            is_external=record.is_external,
                        )
                    )

            call_graph.add_edge(
                caller=record.caller,
                callee=record.callee,
                resolution_method=record.resolution_method,
                location=record.location,
            )

        return call_graph
