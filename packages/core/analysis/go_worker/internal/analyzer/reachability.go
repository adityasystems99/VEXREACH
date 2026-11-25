package analyzer

import (
	"fmt"
	"sort"
	"strings"
)

type graphState struct {
	nodes    map[string]*CallGraphNode
	adj      map[string][]string
	edges    map[string]*CallGraphEdge
	edgeList []CallGraphEdge
	truncated bool
	diags    []AnalysisDiagnostic
}

func buildBoundedGraph(parsed ParsedRepo, maxNodes, maxEdges int) graphState {
	if maxNodes <= 0 {
		maxNodes = 50000
	}
	if maxEdges <= 0 {
		maxEdges = 200000
	}

	gs := graphState{
		nodes:    make(map[string]*CallGraphNode),
		adj:      make(map[string][]string),
		edges:    make(map[string]*CallGraphEdge),
		edgeList: []CallGraphEdge{},
		diags:    []AnalysisDiagnostic{},
	}

	// Add internal functions deterministically
	var keys []string
	for k := range parsed.Functions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(gs.nodes) >= maxNodes {
			gs.truncated = true
			gs.diags = append(gs.diags, AnalysisDiagnostic{
				Code:     "GRAPH_TRUNCATED",
				Severity: "warning",
				Message:  fmt.Sprintf("Go call graph node cap (%d) reached.", maxNodes),
			})
			break
		}
		cp := *parsed.Functions[k]
		gs.nodes[k] = &cp
	}

	ensureExtNode := func(qname string) bool {
		if _, exists := gs.nodes[qname]; exists {
			return true
		}
		if len(gs.nodes) >= maxNodes {
			gs.truncated = true
			gs.diags = append(gs.diags, AnalysisDiagnostic{
				Code:     "GRAPH_TRUNCATED",
				Severity: "warning",
				Message:  fmt.Sprintf("Go call graph node cap (%d) reached while adding '%s'.", maxNodes, qname),
			})
			return false
		}
		mod := qname
		if idx := strings.LastIndex(qname, "."); idx > 0 {
			mod = qname[:idx]
		}
		gs.nodes[qname] = &CallGraphNode{
			NodeID:        qname,
			Module:        mod,
			QualifiedName: qname,
			NodeType:      "external_symbol",
			IsExternal:    true,
		}
		return true
	}

	for _, site := range parsed.RawEdges {
		if !ensureExtNode(site.Caller) || !ensureExtNode(site.Callee) {
			break
		}
		ekey := site.Caller + " -> " + site.Callee + "|" + site.ResolutionMethod
		if existing, ok := gs.edges[ekey]; ok {
			existing.SourceLocations = append(existing.SourceLocations, site.Location)
			continue
		}
		if len(gs.edgeList) >= maxEdges {
			gs.truncated = true
			gs.diags = append(gs.diags, AnalysisDiagnostic{
				Code:     "GRAPH_TRUNCATED",
				Severity: "warning",
				Message:  fmt.Sprintf("Go call graph edge cap (%d) reached.", maxEdges),
			})
			break
		}
		edge := CallGraphEdge{
			Caller:           site.Caller,
			Callee:           site.Callee,
			ResolutionMethod: site.ResolutionMethod,
			SourceLocations:  []CodeLocation{site.Location},
		}
		gs.edges[ekey] = &edge
		gs.adj[site.Caller] = append(gs.adj[site.Caller], site.Callee)
	}

	for _, e := range gs.edges {
		gs.edgeList = append(gs.edgeList, *e)
	}
	sort.Slice(gs.edgeList, func(i, j int) bool {
		if gs.edgeList[i].Caller != gs.edgeList[j].Caller {
			return gs.edgeList[i].Caller < gs.edgeList[j].Caller
		}
		return gs.edgeList[i].Callee < gs.edgeList[j].Callee
	})
	for caller := range gs.adj {
		sort.Strings(gs.adj[caller])
	}
	return gs
}

// AnalyzeGoRepository performs conservative static Go reachability analysis and outputs canonical reports.
func AnalyzeGoRepository(opts Options) (OutputBundle, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 15
	}
	if opts.MaxPaths <= 0 {
		opts.MaxPaths = 50
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 5000
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 5 * 1024 * 1024
	}

	disc, err := DiscoverGoSources(opts.TargetPath, opts.MaxFiles, opts.MaxFileBytes)
	if err != nil {
		return OutputBundle{}, err
	}

	depIdx := BuildDependencyIndex(disc.RootDir, opts.DependencySourceDirs)
	parsed := ParseGoRepository(disc, opts.EntryPointConfig, depIdx.PkgAliases)
	gs := buildBoundedGraph(parsed, opts.MaxNodes, opts.MaxEdges)

	allDiags := make([]AnalysisDiagnostic, 0, len(parsed.Diagnostics)+len(gs.diags))
	allDiags = append(allDiags, parsed.Diagnostics...)
	allDiags = append(allDiags, gs.diags...)
	truncated := disc.Truncated || gs.truncated

	if opts.Manifest == nil {
		allDiags = append(allDiags, AnalysisDiagnostic{
			Code:     "NO_SYMBOL_MANIFEST",
			Severity: "info",
			Message:  "No candidate vulnerable symbol manifest supplied; only Go call graph and entry points constructed.",
		})
	}

	resolvedEPs := make([]EntryPoint, 0, len(parsed.EntryPoints))
	for _, ep := range parsed.EntryPoints {
		if ep.Confidence != "unresolved" {
			resolvedEPs = append(resolvedEPs, ep)
		}
	}

	report := StaticReachabilityReport{
		AnalyzerName:       "vexreach-go-ast",
		AnalyzerVersion:    "0.1.0",
		Language:           "go",
		SourceSnapshotHash: disc.SourceSnapshotHash,
		ManifestSHA256:     opts.ManifestSHA256,
		FilesDiscovered:    disc.FilesDiscovered,
		FilesParsed:        parsed.FilesParsed,
		FilesFailed:        parsed.FilesFailed,
		GraphNodeCount:     len(gs.nodes),
		GraphEdgeCount:     len(gs.edgeList),
		MaxGraphDepth:      opts.MaxDepth,
		MaxCallPaths:       opts.MaxPaths,
		Truncated:          truncated,
		EntryPoints:        parsed.EntryPoints,
		Results:            []ReachabilityResult{},
		UnresolvedCalls:    parsed.Unresolved,
		Diagnostics:        allDiags,
		SupportedSubsetNotes: []string{
			"Static Go AST analysis (package funcs, receiver methods, local vars, closures/goroutines, HTTP & Cobra entry points) with zero target execution.",
			"Conservative resolution flagging reflect.*, plugin.Open, dot imports, dynamic function values, and unresolved interface dispatch as `unresolved`.",
			"Static reachability indicates a possible call path within the supported subset; it does NOT establish runtime execution or exploitability.",
		},
	}

	if opts.Manifest != nil {
		report.VulnerabilitiesAnalyzed = len(opts.Manifest.Entries)
		for _, entry := range opts.Manifest.Entries {
			if len(entry.Symbols) == 0 {
				missingDiag := AnalysisDiagnostic{
					Code:          "MISSING_CANDIDATE_SYMBOLS",
					Severity:      "warning",
					Message:       fmt.Sprintf("No candidate vulnerable symbols defined for '%s' (%s).", entry.VulnerabilityID, entry.Package.Name),
					AffectedScope: entry.Package.Name,
				}
				report.Results = append(report.Results, ReachabilityResult{
					VulnerabilityID:        entry.VulnerabilityID,
					PackageID:              entry.Package.PURL,
					PackageName:            entry.Package.Name,
					Ecosystem:              entry.Package.Ecosystem,
					DependencySymbolStatus: "dependency_source_unavailable",
					Reachable:              nil,
					State:                  "missing_candidate_symbols",
					Path:                   []string{},
					Paths:                  []ReachabilityPath{},
					SupportingEdges:        []CallGraphEdge{},
					UnresolvedCalls:        []UnresolvedCall{},
					AnalysisScope:          "go_ast_call_graph_v1",
					Diagnostics:            []AnalysisDiagnostic{missingDiag},
					EvidenceReferences:     []string{},
				})
				continue
			}

			for i := range entry.Symbols {
				cand := entry.Symbols[i]
				report.CandidateSymbolsEvaluated++
				depStatus, depDiags := depIdx.VerifyCandidateSymbol(cand)
				res := evaluateCandidateGo(
					entry,
					&cand,
					depStatus,
					depDiags,
					resolvedEPs,
					gs,
					parsed.Unresolved,
					parsed.FilesFailed,
					truncated,
					opts.MaxDepth,
					opts.MaxPaths,
				)
				report.Results = append(report.Results, res)
			}
		}
	}

	nodeList := make([]CallGraphNode, 0, len(gs.nodes))
	for _, n := range gs.nodes {
		nodeList = append(nodeList, *n)
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].NodeID < nodeList[j].NodeID })

	return OutputBundle{
		Report: report,
		CallGraph: CallGraphArtifact{
			Language: "go",
			Nodes:    nodeList,
			Edges:    gs.edgeList,
		},
	}, nil
}

func evaluateCandidateGo(
	entry VulnerabilitySymbolEntry,
	cand *CandidateVulnerableSymbol,
	depStatus string,
	depDiags []AnalysisDiagnostic,
	entryPoints []EntryPoint,
	gs graphState,
	unresolved []UnresolvedCall,
	filesFailed int,
	truncated bool,
	maxDepth int,
	maxPaths int,
) ReachabilityResult {
	res := ReachabilityResult{
		VulnerabilityID:        entry.VulnerabilityID,
		PackageID:              entry.Package.PURL,
		PackageName:            entry.Package.Name,
		Ecosystem:              entry.Package.Ecosystem,
		CandidateSymbol:        cand,
		DependencySymbolStatus: depStatus,
		Path:                   []string{},
		Paths:                  []ReachabilityPath{},
		SupportingEdges:        []CallGraphEdge{},
		UnresolvedCalls:        []UnresolvedCall{},
		AnalysisScope:          "go_ast_call_graph_v1",
		Diagnostics:            make([]AnalysisDiagnostic, 0, len(depDiags)),
		EvidenceReferences:     []string{},
	}
	res.Diagnostics = append(res.Diagnostics, depDiags...)
	if cand.EvidenceReference != "" {
		res.EvidenceReferences = append(res.EvidenceReferences, cand.EvidenceReference)
	}

	if depStatus == "not_found_in_dependency_source" {
		res.State = "target_symbol_not_found"
		res.Reachable = nil
		return res
	}

	if len(entryPoints) == 0 {
		res.State = "analysis_incomplete"
		res.Reachable = nil
		res.Diagnostics = append(res.Diagnostics, AnalysisDiagnostic{
			Code:     "NO_ENTRY_POINTS",
			Severity: "warning",
			Message:  "No resolved Go entry points discovered or configured.",
		})
		return res
	}

	target := cand.QualifiedName
	var foundPaths [][]string
	depthExceeded := false

	for _, ep := range entryPoints {
		if len(foundPaths) >= maxPaths {
			break
		}
		paths, hitDepth := findSimplePathsBFS(gs.adj, ep.QualifiedName, target, maxDepth, maxPaths-len(foundPaths))
		if hitDepth {
			depthExceeded = true
		}
		foundPaths = append(foundPaths, paths...)
	}

	if len(foundPaths) > 0 {
		// Sort by shortest path length first
		sort.SliceStable(foundPaths, func(i, j int) bool {
			return len(foundPaths[i]) < len(foundPaths[j])
		})
		edgeLookup := make(map[string]CallGraphEdge)
		for _, e := range gs.edgeList {
			k := e.Caller + " -> " + e.Callee
			if _, ok := edgeLookup[k]; !ok {
				edgeLookup[k] = e
			}
		}

		for _, pNodes := range foundPaths {
			pEdges := make([]CallGraphEdge, 0, len(pNodes))
			for i := 0; i+1 < len(pNodes); i++ {
				if ed, ok := edgeLookup[pNodes[i]+" -> "+pNodes[i+1]]; ok {
					pEdges = append(pEdges, ed)
				}
			}
			res.Paths = append(res.Paths, ReachabilityPath{
				EntryPoint:      pNodes[0],
				TargetSymbol:    target,
				Nodes:           pNodes,
				PathLength:      len(pNodes) - 1,
				SupportingEdges: pEdges,
			})
		}

		best := res.Paths[0]
		t := true
		plen := best.PathLength
		epName := best.EntryPoint
		res.State = "reachable"
		res.Reachable = &t
		res.EntryPoint = &epName
		res.Path = best.Nodes
		res.PathLength = &plen
		if best.SupportingEdges != nil {
			res.SupportingEdges = best.SupportingEdges
		}
		return res
	}

	// Conservative fail-closed checks BEFORE ever claiming no_path_within_supported_subset
	if depthExceeded {
		res.State = "analysis_incomplete"
		res.Reachable = nil
		res.Diagnostics = append(res.Diagnostics, AnalysisDiagnostic{
			Code:     "DEPTH_LIMIT_EXCEEDED",
			Severity: "warning",
			Message:  fmt.Sprintf("Target Go symbol '%s' reachable or still queued past max_depth=%d.", target, maxDepth),
		})
		return res
	}
	if truncated || filesFailed > 0 {
		res.State = "analysis_incomplete"
		res.Reachable = nil
		res.Diagnostics = append(res.Diagnostics, AnalysisDiagnostic{
			Code:     "INCOMPLETE_ANALYSIS",
			Severity: "warning",
			Message:  "Go analysis encountered parse failures or graph/file bounds truncation.",
		})
		return res
	}
	if len(unresolved) > 0 {
		res.State = "unresolved"
		res.Reachable = nil
		res.UnresolvedCalls = append(res.UnresolvedCalls, unresolved...)
		res.Diagnostics = append(res.Diagnostics, AnalysisDiagnostic{
			Code:     "UNRESOLVED_DYNAMIC_DISPATCH",
			Severity: "warning",
			Message:  fmt.Sprintf("%d unresolved dynamic/interface/reflect Go call(s) prevent negative reachability guarantee.", len(unresolved)),
		})
		return res
	}

	f := false
	res.State = "no_path_within_supported_subset"
	res.Reachable = &f
	return res
}

func findSimplePathsBFS(adj map[string][]string, start, target string, maxDepth, limit int) ([][]string, bool) {
	if limit <= 0 {
		return nil, false
	}
	if start == target {
		return nil, false
	}

	type queueItem struct {
		path []string
	}
	queue := []queueItem{{path: []string{start}}}
	var results [][]string
	hitDepth := false
	bestDepth := make(map[string]int)
	bestDepth[start] = 0

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		last := cur.path[len(cur.path)-1]
		curEdges := len(cur.path) - 1

		neighbors := adj[last]
		for _, nxt := range neighbors {
			inPath := false
			for _, p := range cur.path {
				if p == nxt {
					inPath = true
					break
				}
			}
			if inPath {
				continue
			}

			nextEdges := curEdges + 1
			if nextEdges > maxDepth {
				// Explore unbounded existence? Note: we know a neighbor beyond maxDepth exists!
				if nxt == target || canReachUnbounded(adj, nxt, target, cur.path) {
					hitDepth = true
				}
				continue
			}

			nextPath := make([]string, len(cur.path)+1)
			copy(nextPath, cur.path)
			nextPath[len(cur.path)] = nxt

			if nxt == target {
				results = append(results, nextPath)
				if len(results) >= limit {
					return results, hitDepth
				}
				continue
			}

			if prevD, seen := bestDepth[nxt]; !seen || nextEdges <= prevD+1 {
				if !seen || nextEdges < prevD {
					bestDepth[nxt] = nextEdges
				}
				queue = append(queue, queueItem{path: nextPath})
			}
		}
	}
	return results, hitDepth
}

func canReachUnbounded(adj map[string][]string, start, target string, forbidden []string) bool {
	if start == target {
		return true
	}
	visited := make(map[string]bool)
	for _, f := range forbidden {
		visited[f] = true
	}
	visited[start] = true
	q := []string{start}
	steps := 0
	for len(q) > 0 && steps < 2000 {
		cur := q[0]
		q = q[1:]
		steps++
		for _, nxt := range adj[cur] {
			if nxt == target {
				return true
			}
			if !visited[nxt] {
				visited[nxt] = true
				q = append(q, nxt)
			}
		}
	}
	return false
}
