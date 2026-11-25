"""Unit tests for Python source discovery, AST parsing, and symbol extraction."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from packages.core.analysis.python.discovery import (
    PythonSourceDiscovery,
    derive_module_identity,
)
from packages.core.analysis.python.parser import parse_python_module
from packages.core.analysis.python.symbols import extract_module_symbols
from packages.core.config.settings import Settings


@pytest.mark.unit
def test_derive_module_identity_handles_src_layout_and_packages() -> None:
    assert derive_module_identity("main.py") == ("main", (), False)
    assert derive_module_identity("app/__init__.py") == ("app", ("app",), True)
    assert derive_module_identity("app/sub/mod.py") == ("app.sub.mod", ("app", "sub"), False)
    assert derive_module_identity("src/pkg/client.py", strip_src_root=True) == (
        "pkg.client",
        ("pkg",),
        False,
    )
    assert derive_module_identity("src/pkg/__init__.py", strip_src_root=True) == (
        "pkg",
        ("pkg",),
        True,
    )


@pytest.mark.unit
def test_discovery_ignores_venvs_caches_large_files_and_truncates(tmp_path: Path) -> None:
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "ignored.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "ignored.py").write_text("x = 2\n", encoding="utf-8")

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "app" / "ok.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (tmp_path / "app" / "big.py").write_text("x = '" + ("a" * 500) + "'\n", encoding="utf-8")

    discovery = PythonSourceDiscovery(
        settings=Settings(max_file_size_bytes=200, max_python_files=100)
    )
    res = discovery.discover(tmp_path)
    rel_paths = [f.relative_path for f in res.files]

    assert rel_paths == ["app/__init__.py", "app/ok.py"]
    assert all("\\" not in p for p in rel_paths)
    assert any(d.code == "FILE_TOO_LARGE" for d in res.diagnostics)
    assert len(res.source_snapshot_hash) == 64

    # Enforce max_python_files cap
    capped = PythonSourceDiscovery(settings=Settings(max_python_files=1)).discover(tmp_path)
    assert len(capped.files) == 1
    assert capped.truncated is True
    assert any(d.code == "PYTHON_FILE_LIMIT_EXCEEDED" for d in capped.diagnostics)


@pytest.mark.unit
def test_discovery_skips_symlinks_safely(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("def secret(): pass\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("def main(): pass\n", encoding="utf-8")
    link_path = repo / "link.py"
    try:
        os.symlink(outside, link_path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires elevated privileges on this Windows host")

    res = PythonSourceDiscovery().discover(repo)
    assert [f.relative_path for f in res.files] == ["main.py"]
    assert any(d.code == "SYMLINK_SKIPPED" for d in res.diagnostics)


@pytest.mark.unit
def test_parser_reports_syntax_error_and_unicode_error_without_crash(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00\x80")

    discovery = PythonSourceDiscovery().discover(tmp_path)
    by_path = {f.relative_path: parse_python_module(f) for f in discovery.files}

    assert not by_path["broken.py"].parsed_successfully
    assert any(d.code == "SYNTAX_ERROR" for d in by_path["broken.py"].diagnostics)
    assert not by_path["binary.py"].parsed_successfully
    assert any(d.code == "UNICODE_DECODE_ERROR" for d in by_path["binary.py"].diagnostics)


@pytest.mark.unit
def test_symbol_extraction_functions_classes_nested_main_and_types(tmp_path: Path) -> None:
    src = '''\ufefffrom fastapi import FastAPI

app = FastAPI()


class Service:
    def run(self, client: Client):
        def inner():
            return 1
        c = Helper()
        return inner()


@app.get("/health")
async def health():
    return "ok"


if __name__ == "__main__":
    health()
'''
    (tmp_path / "svc.py").write_text(src, encoding="utf-8")
    py_file = PythonSourceDiscovery().discover(tmp_path).files[0]
    parsed = parse_python_module(py_file)
    symbols = extract_module_symbols(parsed)

    assert "svc.Service" in symbols.classes
    assert "svc.Service.run" in symbols.functions
    assert "svc.Service.run.<locals>.inner" in symbols.functions
    assert "svc.health" in symbols.functions
    assert "svc.__main__" in symbols.functions
    assert symbols.functions["svc.health"].node_type == "async_function"
    assert symbols.functions["svc.Service.run"].param_annotations["client"] == "Client"
    assert symbols.functions["svc.Service.run"].local_var_types["c"] == "Helper"
    assert symbols.module_var_types["app"] == "FastAPI"
    assert symbols.functions["svc.health"].decorators[0].args_preview == ["/health"]
