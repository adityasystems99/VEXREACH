# ADR-002: Language Strategy - Python Core First, Go Ecosystem Second

## Status
Accepted

## Context
VEXReach intends to support vulnerability reachability analysis for applications written in multiple modern programming languages, with primary targets being **Python** and **Go**.

Building static analysis tools (call graph construction, AST extraction, points-to analysis) requires deep language-specific tooling:
- For Python: `ast`, `symtable`, `tree-sitter`, `dis`.
- For Go: `go/parser`, `go/ast`, `go/types`, `golang.org/x/tools/go/callgraph` (CHA, RTA, VTA).

Attempting to build both static analyzers simultaneously from day one creates severe cognitive overhead, duplicates debugging complexity, and delays the realization of an end-to-end working pipeline (from SBOM $\to$ Reachability $\to$ OpenVEX).

Furthermore, Python is the premier language for AI orchestration, graph modeling (`networkx`), and rapid security tooling integration, while Go is the premier language for Kubernetes operators and native Go source analysis.

## Decision
1. **Core Platform in Python**:
   - The entire orchestration platform, discovery engine, risk engine, policy evaluator, OpenVEX generator, and the **Python Application Reachability Analyzer** will be implemented in Python 3.12+.
2. **Go Implementation Deferred to Phase 9**:
   - The Go Application Reachability Analyzer will be introduced only after the Python analysis pipeline has passed all acceptance tests (Test A through Test F).
   - Go analysis will be implemented as an explicit Go binary or service utilizing `golang.org/x/tools` and invoked by the Python core via structured JSON contracts (`contracts/analysis_contract.json`).
3. **Separation of Operator Language vs. Analyzed Language**:
   - The planned Kubernetes Operator (Phase 11) will be written in Go using Kubebuilder / controller-runtime, operating as an orchestrator that deploys VEXReach core analysis containers. The language of the Operator is distinct from the language of the application being analyzed.

## Consequences

### Positive
- Delivers a functional, end-to-end working MVP rapidly without language context switching.
- Allows rigorous testing of core vulnerability decision policies on Python before tackling Go's interface dispatch, goroutines, and reflection.
- Preserves a clean contract interface (`analysis_contract.json`) that enables adding other languages (Java, Rust, Node.js) in the future.

### Negative / Trade-offs
- Teams with pure Go applications must await Phase 9 before VEXReach can parse their call graphs.
