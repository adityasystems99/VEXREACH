# Cross-Language Static Reachability Analysis Contract

[`analysis_contract.json`](./analysis_contract.json) defines the versioned JSON schema bridging language-specific static analyzers (Python AST, Go AST/`go/types`) with the VEXReach core orchestrator, Attack Path Intelligence, Risk Intelligence, and OpenVEX Policy Engine.

## Contract Principles
1. **Strict Evidence Separation**: All analyzers must separate candidate symbol resolution (`dependency_symbol_status`), call-graph reachability (`state`), unresolved dynamic dispatch (`unresolved_calls`), and truncation/errors (`truncated`, `diagnostics`).
2. **Fail-Closed Negative States**: `no_path_within_supported_subset` is valid only when zero unresolved dynamic/interface dispatch constructs prevent path enumeration; dynamic constructs (`reflect`, interfaces without concrete resolution, `getattr`, `eval`) must yield `unresolved`.
3. **Zero Execution**: Analyzers inspect source ASTs, type metadata, and `go.mod`/manifests only — never importing, compiling, or running untrusted target code (`init()`, `main()`, test hooks).
