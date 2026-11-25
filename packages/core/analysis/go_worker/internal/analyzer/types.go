// Package analyzer implements a conservative, zero-execution Go AST static reachability analyzer
// conforming to VEXReach contracts/analysis_contract.json.
package analyzer

// CodeLocation represents a portable repository-relative source code location.
type CodeLocation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	EndLine *int   `json:"end_line,omitempty"`
}

// EntryPointRule models a single user-configured entry point.
type EntryPointRule struct {
	Module        string `json:"module"`
	QualifiedName string `json:"qualified_name"`
	Source        string `json:"source,omitempty"`
}

// EntryPointConfig loads explicit entry_points.json files.
type EntryPointConfig struct {
	EntryPoints []EntryPointRule `json:"entry_points"`
}

// SymbolPackageTarget matches VulnerabilitySymbolEntry.package.
type SymbolPackageTarget struct {
	Ecosystem   string   `json:"ecosystem"`
	Name        string   `json:"name"`
	Version     *string  `json:"version,omitempty"`
	PURL        *string  `json:"purl,omitempty"`
	ImportNames []string `json:"import_names,omitempty"`
}

// SymbolEvidence captures symbol provenance.
type SymbolEvidence struct {
	Source                       string `json:"source"`
	EvidenceReference            string `json:"evidence_reference,omitempty"`
	Confidence                   string `json:"confidence"`
	Notes                        string `json:"notes,omitempty"`
	VerifiedByDeterministicCheck bool   `json:"verified_by_deterministic_check"`
}

// CandidateVulnerableSymbol represents one candidate function/method to trace.
type CandidateVulnerableSymbol struct {
	Module            string          `json:"module"`
	QualifiedName     string          `json:"qualified_name"`
	SymbolType        string          `json:"symbol_type"`
	Source            string          `json:"source"`
	EvidenceReference string          `json:"evidence_reference,omitempty"`
	Confidence        string          `json:"confidence"`
	Evidence          *SymbolEvidence `json:"evidence,omitempty"`
}

// VulnerabilitySymbolEntry groups candidate symbols under a vulnerability + package.
type VulnerabilitySymbolEntry struct {
	VulnerabilityID string                      `json:"vulnerability_id"`
	Package         SymbolPackageTarget         `json:"package"`
	Symbols         []CandidateVulnerableSymbol `json:"symbols"`
}

// VulnerabilitySymbolManifest represents validated symbol manifest inputs.
type VulnerabilitySymbolManifest struct {
	ManifestVersion string                     `json:"manifest_version"`
	Entries         []VulnerabilitySymbolEntry `json:"entries"`
}

// EntryPoint identifies a traversal root function or HTTP/CLI handler.
type EntryPoint struct {
	QualifiedName string            `json:"qualified_name"`
	Module        string            `json:"module"`
	Source        string            `json:"source"`
	Confidence    string            `json:"confidence"`
	Location      *CodeLocation     `json:"location,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// CallGraphNode represents a node in the exported Go call graph artifact.
type CallGraphNode struct {
	NodeID        string        `json:"node_id"`
	Module        string        `json:"module"`
	QualifiedName string        `json:"qualified_name"`
	NodeType      string        `json:"node_type"`
	IsExternal    bool          `json:"is_external"`
	IsEntryPoint  bool          `json:"is_entry_point"`
	Location      *CodeLocation `json:"location,omitempty"`
	Decorators    []string      `json:"decorators,omitempty"`
}

// CallGraphEdge represents a directed call edge with call-site locations.
type CallGraphEdge struct {
	Caller           string         `json:"caller"`
	Callee           string         `json:"callee"`
	ResolutionMethod string         `json:"resolution_method"`
	SourceLocations  []CodeLocation `json:"source_locations"`
}

// UnresolvedCall captures dynamic reflection, plugin, or unresolved indirect calls.
type UnresolvedCall struct {
	Caller        string       `json:"caller"`
	RawExpression string       `json:"raw_expression"`
	Category      string       `json:"category"`
	Reason        string       `json:"reason"`
	Location      CodeLocation `json:"location"`
}

// AnalysisDiagnostic captures errors, truncation, or analysis caveats.
type AnalysisDiagnostic struct {
	Code          string        `json:"code"`
	Severity      string        `json:"severity"`
	Message       string        `json:"message"`
	Location      *CodeLocation `json:"location,omitempty"`
	ConstructKind string        `json:"construct_kind,omitempty"`
	AffectedScope string        `json:"affected_scope,omitempty"`
}

// ReachabilityPath records a single simple call path from an entry point to target symbol.
type ReachabilityPath struct {
	EntryPoint      string          `json:"entry_point"`
	TargetSymbol    string          `json:"target_symbol"`
	Nodes           []string        `json:"nodes"`
	PathLength      int             `json:"path_length"`
	SupportingEdges []CallGraphEdge `json:"supporting_edges"`
}

// ReachabilityResult matches canonical VEXReach per-finding reachability schema.
type ReachabilityResult struct {
	VulnerabilityID        string                     `json:"vulnerability_id"`
	PackageID              *string                    `json:"package_id,omitempty"`
	PackageName            string                     `json:"package_name"`
	Ecosystem              string                     `json:"ecosystem"`
	CandidateSymbol        *CandidateVulnerableSymbol `json:"candidate_symbol,omitempty"`
	DependencySymbolStatus string                     `json:"dependency_symbol_status"`
	EntryPoint             *string                    `json:"entry_point,omitempty"`
	Reachable              *bool                      `json:"reachable"`
	State                  string                     `json:"state"`
	Path                   []string                   `json:"path"`
	Paths                  []ReachabilityPath         `json:"paths"`
	PathLength             *int                       `json:"path_length,omitempty"`
	SupportingEdges        []CallGraphEdge            `json:"supporting_edges"`
	UnresolvedCalls        []UnresolvedCall           `json:"unresolved_calls"`
	AnalysisScope          string                     `json:"analysis_scope"`
	Diagnostics            []AnalysisDiagnostic       `json:"diagnostics"`
	EvidenceReferences     []string                   `json:"evidence_references"`
}

// StaticReachabilityReport matches packages/core/models/reachability.py StaticReachabilityReport.
type StaticReachabilityReport struct {
	AnalysisID                string               `json:"analysis_id,omitempty"`
	AnalyzerName              string               `json:"analyzer_name"`
	AnalyzerVersion           string               `json:"analyzer_version"`
	Language                  string               `json:"language"`
	SourceSnapshotHash        string               `json:"source_snapshot_hash,omitempty"`
	ManifestSHA256            string               `json:"manifest_sha256,omitempty"`
	FilesDiscovered           int                  `json:"files_discovered"`
	FilesParsed               int                  `json:"files_parsed"`
	FilesFailed               int                  `json:"files_failed"`
	GraphNodeCount            int                  `json:"graph_node_count"`
	GraphEdgeCount            int                  `json:"graph_edge_count"`
	MaxGraphDepth             int                  `json:"max_graph_depth"`
	MaxCallPaths              int                  `json:"max_call_paths"`
	Truncated                 bool                 `json:"truncated"`
	VulnerabilitiesAnalyzed   int                  `json:"vulnerabilities_analyzed"`
	CandidateSymbolsEvaluated int                  `json:"candidate_symbols_evaluated"`
	EntryPoints               []EntryPoint         `json:"entry_points"`
	Results                   []ReachabilityResult `json:"results"`
	UnresolvedCalls           []UnresolvedCall     `json:"unresolved_calls"`
	Diagnostics               []AnalysisDiagnostic `json:"diagnostics"`
	SupportedSubsetNotes      []string             `json:"supported_subset_notes"`
}

// CallGraphArtifact holds serializable graph nodes and edges.
type CallGraphArtifact struct {
	Language string          `json:"language"`
	Nodes    []CallGraphNode `json:"nodes"`
	Edges    []CallGraphEdge `json:"edges"`
}

// OutputBundle is emitted on stdout or --out to bridge seamlessly into Python orchestrators.
type OutputBundle struct {
	Report    StaticReachabilityReport `json:"report"`
	CallGraph CallGraphArtifact        `json:"call_graph"`
}

// Options tunes conservative safety bounds for Go source discovery and traversal.
type Options struct {
	TargetPath            string
	Manifest              *VulnerabilitySymbolManifest
	ManifestSHA256        string
	EntryPointConfig      *EntryPointConfig
	DependencySourceDirs  []string
	MaxDepth              int
	MaxPaths              int
	MaxFiles              int
	MaxFileBytes          int64
	MaxNodes              int
	MaxEdges              int
}
