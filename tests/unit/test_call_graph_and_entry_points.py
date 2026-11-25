"""Unit tests for NetworkX call graph construction and entry-point detectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.core.analysis.python.call_graph import PythonCallGraph, PythonCallGraphBuilder
from packages.core.analysis.python.discovery import PythonSourceDiscovery
from packages.core.analysis.python.entry_points import EntryPointDetector
from packages.core.analysis.python.imports import extract_import_table
from packages.core.analysis.python.parser import parse_python_module
from packages.core.analysis.python.resolver import (
    PythonCallResolver,
    RepositoryModuleIndex,
    ResolutionOutcome,
    ResolvedCallRecord,
)
from packages.core.analysis.python.symbols import extract_module_symbols
from packages.core.config.settings import Settings
from packages.core.models.reachability import CodeLocation, EntryPointConfig, EntryPointRule


@pytest.mark.unit
def test_call_graph_deduplicates_edges_and_enforces_limits() -> None:
    builder = PythonCallGraphBuilder(
        settings=Settings(max_graph_nodes=10, max_graph_edges=10)
    )
    index = RepositoryModuleIndex()
    outcome = ResolutionOutcome()
    loc1 = CodeLocation(file="a.py", line=5, column=4)
    loc2 = CodeLocation(file="a.py", line=9, column=4)

    # Empty internal index -> external calls test node cap & multi-location merging
    cg = PythonCallGraph(max_nodes=3, max_edges=2)
    from packages.core.models.reachability import CallGraphNode

    assert cg.add_node(CallGraphNode(node_id="a", module="m", qualified_name="a", node_type="function"))
    assert cg.add_node(CallGraphNode(node_id="b", module="m", qualified_name="b", node_type="function"))
    assert cg.add_node(CallGraphNode(node_id="c", module="m", qualified_name="c", node_type="external_symbol", is_external=True))
    # 4th node triggers truncation
    assert not cg.add_node(CallGraphNode(node_id="d", module="m", qualified_name="d", node_type="external_symbol", is_external=True))
    assert cg.truncated is True

    assert cg.add_edge(caller="a", callee="b", resolution_method="direct", location=loc1)
    assert cg.add_edge(caller="a", callee="b", resolution_method="direct", location=loc2)
    assert len(cg.edges[("a", "b")].source_locations) == 2

    serial = cg.to_serializable_dict()
    assert serial["node_count"] == 3
    assert serial["edge_count"] == 1
    assert isinstance(builder.build(index, outcome), PythonCallGraph)
    assert ResolvedCallRecord(caller="a", callee="b", resolution_method="direct", is_external=False, location=loc1).caller == "a"


@pytest.mark.unit
def test_call_graph_cycles_path_limit_and_depth_cutoff() -> None:
    from packages.core.models.reachability import CallGraphNode

    cg = PythonCallGraph()
    loc = CodeLocation(file="m.py", line=1)
    for nid in ("entry", "a", "b", "c", "target"):
        cg.add_node(CallGraphNode(node_id=nid, module="m", qualified_name=nid, node_type="function"))

    # Cyclic edges + deeper path entry -> a -> b -> c -> target
    cg.add_edge(caller="entry", callee="a", resolution_method="direct", location=loc)
    cg.add_edge(caller="a", callee="b", resolution_method="direct", location=loc)
    cg.add_edge(caller="b", callee="a", resolution_method="direct", location=loc)
    cg.add_edge(caller="b", callee="c", resolution_method="direct", location=loc)
    cg.add_edge(caller="c", callee="target", resolution_method="direct", location=loc)

    # Cutoff too small for length-4 path: depth_limit_exceeded must be True
    shallow = cg.find_paths(["entry"], "target", max_depth=2, max_paths=10)
    assert shallow.paths == []
    assert shallow.depth_limit_exceeded is True

    # Cutoff large enough: terminates cleanly despite a <-> b cycle
    deep = cg.find_paths(["entry"], "target", max_depth=6, max_paths=10)
    assert len(deep.paths) == 1
    assert deep.paths[0].nodes == ["entry", "a", "b", "c", "target"]
    assert deep.depth_limit_exceeded is False


@pytest.mark.unit
def test_entry_point_detectors_and_missing_entry_diagnostics(tmp_path: Path) -> None:
    (tmp_path / "web.py").write_text(
        "from fastapi import APIRouter\n"
        "from flask import Blueprint\n"
        "import click\n\n"
        "router = APIRouter()\n"
        "bp = Blueprint('v1', __name__)\n\n"
        "@router.post('/submit')\n"
        "def api_submit():\n"
        "    return 1\n\n"
        "@bp.route('/bp')\n"
        "def flask_view():\n"
        "    return 'ok'\n\n"
        "@click.command()\n"
        "def cli_cmd():\n"
        "    return 0\n\n"
        "if __name__ == '__main__':\n"
        "    cli_cmd()\n",
        encoding="utf-8",
    )

    disc = PythonSourceDiscovery().discover(tmp_path)
    parsed = parse_python_module(disc.files[0])
    sym = extract_module_symbols(parsed)
    imp = extract_import_table(parsed, sym)
    index = RepositoryModuleIndex.build([sym], [imp])

    cfg = EntryPointConfig(
        entry_points=[
            EntryPointRule(module="web", qualified_name="api_submit"),
            EntryPointRule(module="web", qualified_name="missing_func"),
        ]
    )
    ep_res = EntryPointDetector().detect(index, config=cfg)
    sources_by_qname = {(ep.qualified_name, ep.source): ep.confidence for ep in ep_res.entry_points}

    assert sources_by_qname[("web.api_submit", "fastapi_route")] == "verified"
    assert sources_by_qname[("web.api_submit", "user_config")] == "verified"
    assert sources_by_qname[("web.flask_view", "flask_route")] == "verified"
    assert sources_by_qname[("web.cli_cmd", "click_command")] == "verified"
    assert sources_by_qname[("web.__main__", "python_main_block")] == "verified"
    assert sources_by_qname[("web.missing_func", "user_config")] == "unresolved"
    assert any(d.code == "CONFIGURED_ENTRY_POINT_NOT_FOUND" for d in ep_res.diagnostics)
