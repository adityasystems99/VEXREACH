"""Unit tests for Python import binding extraction and static call resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.core.analysis.python.discovery import PythonSourceDiscovery
from packages.core.analysis.python.imports import extract_import_table
from packages.core.analysis.python.parser import parse_python_module
from packages.core.analysis.python.resolver import (
    PythonCallResolver,
    RepositoryModuleIndex,
)
from packages.core.analysis.python.symbols import extract_module_symbols


def _resolve_repo(repo_dir: Path):
    disc = PythonSourceDiscovery().discover(repo_dir)
    parsed_mods = [parse_python_module(f) for f in disc.files]
    mod_syms = []
    imp_tables = []
    for p in parsed_mods:
        assert p.parsed_successfully, p.diagnostics
        sym = extract_module_symbols(p)
        imp = extract_import_table(p, sym)
        mod_syms.append(sym)
        imp_tables.append(imp)
    index = RepositoryModuleIndex.build(mod_syms, imp_tables)
    outcome = PythonCallResolver().resolve_repository(index)
    return index, outcome, imp_tables


@pytest.mark.unit
def test_relative_aliased_and_wildcard_imports(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "utils.py").write_text(
        "import yaml\n\ndef parse(s: str):\n    return yaml.load(s)\n",
        encoding="utf-8",
    )
    (tmp_path / "pkg" / "sub").mkdir()
    (tmp_path / "pkg" / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "sub" / "views.py").write_text(
        "from ..utils import parse as parse_yaml\n"
        "from urllib.request import urlopen\n"
        "import xml.etree.ElementTree as ET\n"
        "from wildcard_mod import *\n"
        "from .....too_far import x\n\n"
        "def local_importer():\n"
        "    import json as j\n"
        "    return j.loads('{}')\n\n"
        "def run_all(raw: str):\n"
        "    parse_yaml(raw)\n"
        "    urlopen('https://example.invalid')\n"
        "    return ET.fromstring(raw)\n",
        encoding="utf-8",
    )

    _, outcome, imp_tables = _resolve_repo(tmp_path)
    edges = {(c.caller, c.callee) for c in outcome.resolved_calls}

    assert ("pkg.sub.views.run_all", "pkg.utils.parse") in edges
    assert ("pkg.utils.parse", "yaml.load") in edges
    assert ("pkg.sub.views.run_all", "urllib.request.urlopen") in edges
    assert ("pkg.sub.views.run_all", "xml.etree.ElementTree.fromstring") in edges
    assert ("pkg.sub.views.local_importer", "json.loads") in edges

    all_imp_diags = [d for t in imp_tables for d in t.diagnostics]
    assert any(d.code == "WILDCARD_IMPORT" for d in all_imp_diags)
    assert any(d.code == "RELATIVE_IMPORT_BEYOND_TOP_LEVEL" for d in all_imp_diags)


@pytest.mark.unit
def test_class_inheritance_instance_typed_param_and_dynamic_detection(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import importlib\n"
        "import yaml\n\n"
        "class Base:\n"
        "    def sink(self, raw: str):\n"
        "        return yaml.load(raw)\n\n"
        "class Child(Base):\n"
        "    def run(self, raw: str):\n"
        "        return self.sink(raw)\n\n"
        "def typed_caller(c: Child, raw: str):\n"
        "    return c.run(raw)\n\n"
        "def dynamic_cases(name: str, handlers):\n"
        "    fn = getattr(yaml, name)\n"
        "    eval('1 + 1')\n"
        "    exec('x = 1')\n"
        "    __import__('os')\n"
        "    importlib.import_module('math')\n"
        "    handlers[name]()\n"
        "    return fn\n",
        encoding="utf-8",
    )

    _, outcome, _ = _resolve_repo(tmp_path)
    edges = {(c.caller, c.callee) for c in outcome.resolved_calls}
    assert ("app.typed_caller", "app.Child.run") in edges
    assert ("app.Child.run", "app.Base.sink") in edges
    assert ("app.Base.sink", "yaml.load") in edges

    categories = {u.category for u in outcome.unresolved_calls}
    assert "dynamic_attribute_lookup" in categories
    assert "dynamic_code_execution" in categories
    assert "dynamic_import" in categories
    assert "dynamic_subscript_call" in categories
