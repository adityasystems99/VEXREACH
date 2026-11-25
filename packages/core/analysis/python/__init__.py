"""Python AST-based static reachability analysis package."""

from packages.core.analysis.python.call_graph import (
    PathSearchResult,
    PythonCallGraph,
    PythonCallGraphBuilder,
)
from packages.core.analysis.python.dependency_symbols import (
    DependencySymbolCheck,
    DependencySymbolResolver,
    canonicalize_pypi_name,
    load_symbol_manifest,
)
from packages.core.analysis.python.discovery import (
    DiscoveredPythonFile,
    PythonDiscoveryResult,
    PythonSourceDiscovery,
)
from packages.core.analysis.python.entry_points import (
    EntryPointDetectionResult,
    EntryPointDetector,
    load_entry_point_config,
)
from packages.core.analysis.python.imports import (
    ImportBinding,
    ImportTable,
    extract_import_table,
)
from packages.core.analysis.python.parser import (
    ParsedPythonModule,
    parse_python_module,
)
from packages.core.analysis.python.reachability import (
    PythonReachabilityAnalyzer,
    ReachabilityAnalysisBundle,
)
from packages.core.analysis.python.resolver import (
    PythonCallResolver,
    RepositoryModuleIndex,
    ResolutionOutcome,
    ResolvedCallRecord,
)
from packages.core.analysis.python.symbols import (
    ClassSymbol,
    DecoratorInfo,
    FunctionSymbol,
    ModuleSymbols,
    extract_module_symbols,
)

__all__ = [
    "ClassSymbol",
    "DecoratorInfo",
    "DependencySymbolCheck",
    "DependencySymbolResolver",
    "DiscoveredPythonFile",
    "EntryPointDetectionResult",
    "EntryPointDetector",
    "FunctionSymbol",
    "ImportBinding",
    "ImportTable",
    "ModuleSymbols",
    "ParsedPythonModule",
    "PathSearchResult",
    "PythonCallGraph",
    "PythonCallGraphBuilder",
    "PythonCallResolver",
    "PythonDiscoveryResult",
    "PythonReachabilityAnalyzer",
    "PythonSourceDiscovery",
    "ReachabilityAnalysisBundle",
    "RepositoryModuleIndex",
    "ResolutionOutcome",
    "ResolvedCallRecord",
    "canonicalize_pypi_name",
    "extract_import_table",
    "extract_module_symbols",
    "load_entry_point_config",
    "load_symbol_manifest",
    "parse_python_module",
]
