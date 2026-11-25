package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var goVersionSuffixRe = regexp.MustCompile(`^v\d+$`)

var goBuiltins = map[string]bool{
	"append": true, "cap": true, "clear": true, "close": true, "complex": true,
	"copy": true, "delete": true, "imag": true, "len": true, "make": true,
	"max": true, "min": true, "new": true, "panic": true, "print": true,
	"println": true, "real": true, "recover": true,
	// Standard primitive type conversions in Go AST (*ast.CallExpr)
	"any": true, "bool": true, "byte": true, "complex64": true, "complex128": true,
	"error": true, "float32": true, "float64": true, "int": true, "int8": true,
	"int16": true, "int32": true, "int64": true, "rune": true, "string": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true,
}

var knownStdlibReceiverPrefixes = map[string]bool{
	"http": true, "io": true, "fmt": true, "bytes": true, "strings": true,
	"context": true, "sync": true, "time": true, "json": true, "url": true,
	"os": true, "bufio": true, "log": true, "errors": true, "filepath": true,
}

// CallEdgeSite records a single statically resolved call from caller to callee.
type CallEdgeSite struct {
	Caller           string
	Callee           string
	ResolutionMethod string
	Location         CodeLocation
}

// ParsedRepo collects extracted functions, calls, entry points, and unresolved dynamic calls.
type ParsedRepo struct {
	Discovery       DiscoverySummary
	FilesParsed     int
	FilesFailed     int
	Functions       map[string]*CallGraphNode // key: node_id
	PkgSimpleFuncs  map[string]map[string]string
	PkgMethods      map[string]map[string]map[string]string // pkg -> type -> method -> node_id
	FuncReturnTypes map[string]string                       // func_node_id -> qualified type name
	EntryPoints     []EntryPoint
	EntrySet        map[string]bool
	RawEdges        []CallEdgeSite
	Unresolved      []UnresolvedCall
	Diagnostics     []AnalysisDiagnostic
}

func defaultGoImportAlias(importPath string) string {
	clean := strings.Trim(importPath, `"`)
	base := path.Base(clean)
	if goVersionSuffixRe.MatchString(base) {
		parent := path.Base(path.Dir(clean))
		if parent != "." && parent != "/" && parent != "" {
			if idx := strings.LastIndex(parent, "."); idx > 0 {
				// Handle gopkg.in/yaml.v2 -> dir="gopkg.in" if path was gopkg.in/yaml.v2 (path.Base is "yaml.v2")
				return parent
			}
			return sanitizePkgIdent(parent)
		}
	}
	// Handle gopkg.in/yaml.v2 -> yaml
	if idx := strings.Index(base, ".v"); idx > 0 {
		return sanitizePkgIdent(base[:idx])
	}
	return sanitizePkgIdent(base)
}

func sanitizePkgIdent(s string) string {
	s = strings.ReplaceAll(s, "-", "_")
	if i := strings.Index(s, "."); i > 0 {
		s = s[:i]
	}
	return s
}

func exprToTypeString(expr ast.Expr, curPkg string, imports map[string]string) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return exprToTypeString(t.X, curPkg, imports)
	case *ast.Ident:
		if t.Name == "error" || t.Name == "any" || t.Name == "string" || t.Name == "int" {
			return t.Name
		}
		return curPkg + "." + t.Name
	case *ast.SelectorExpr:
		if pkgIdent, ok := t.X.(*ast.Ident); ok {
			if impPath, isImp := imports[pkgIdent.Name]; isImp {
				return impPath + "." + t.Sel.Name
			}
			return pkgIdent.Name + "." + t.Sel.Name
		}
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	}
	return ""
}

func receiverBaseType(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	switch t := recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func exprText(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprText(e.X) + "." + e.Sel.Name
	case *ast.IndexExpr:
		return exprText(e.X) + "[...]"
	case *ast.CallExpr:
		return exprText(e.Fun) + "(...)"
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func isHTTPRegisterMethod(name string) bool {
	switch name {
	case "HandleFunc", "Handle", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "Any", "Method":
		return true
	}
	return false
}

// ParseGoRepository parses discovered Go files and extracts static symbols, entry points, and call edges.
func ParseGoRepository(discovery DiscoverySummary, epConfig *EntryPointConfig, depPkgAliases map[string]string) ParsedRepo {
	parsed := ParsedRepo{
		Discovery:       discovery,
		Functions:       make(map[string]*CallGraphNode),
		PkgSimpleFuncs:  make(map[string]map[string]string),
		PkgMethods:      make(map[string]map[string]map[string]string),
		FuncReturnTypes: make(map[string]string),
		EntryPoints:     []EntryPoint{},
		EntrySet:        make(map[string]bool),
		RawEdges:        []CallEdgeSite{},
		Unresolved:      []UnresolvedCall{},
		Diagnostics:     make([]AnalysisDiagnostic, 0, len(discovery.Diagnostics)),
	}
	parsed.Diagnostics = append(parsed.Diagnostics, discovery.Diagnostics...)

	type parsedFileRec struct {
		file       DiscoveredGoFile
		fset       *token.FileSet
		astFile    *ast.File
		imports    map[string]string // local alias -> full import path
		dotImports []string
		pkgName    string
	}

	var loadedFiles []parsedFileRec
	fset := token.NewFileSet()

	// Pass 1: parse files and index every declared function / method and its return type
	for _, gf := range discovery.Files {
		astF, err := parser.ParseFile(fset, gf.AbsPath, nil, parser.ParseComments)
		if err != nil {
			parsed.FilesFailed++
			parsed.Diagnostics = append(parsed.Diagnostics, AnalysisDiagnostic{
				Code:     "PARSE_ERROR",
				Severity: "error",
				Message:  err.Error(),
				Location: &CodeLocation{File: gf.RelPOSIX, Line: 1, Column: 0},
			})
			continue
		}
		parsed.FilesParsed++

		imports := make(map[string]string)
		var dotImports []string
		for _, imp := range astF.Imports {
			impPath, uErr := strconv.Unquote(imp.Path.Value)
			if uErr != nil {
				continue
			}
			var alias string
			if imp.Name != nil {
				alias = imp.Name.Name
			} else if knownAlias, ok := depPkgAliases[impPath]; ok {
				alias = knownAlias
			} else {
				alias = defaultGoImportAlias(impPath)
			}
			if alias == "_" {
				continue
			}
			if alias == "." {
				dotImports = append(dotImports, impPath)
				pos := fset.Position(imp.Pos())
				parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
					Caller:        gf.ImportPkg,
					RawExpression: "import . \"" + impPath + "\"",
					Category:      "dot_import_uncertainty",
					Reason:        "Dot imports inject external identifiers into package scope without explicit module qualification.",
					Location:      CodeLocation{File: gf.RelPOSIX, Line: pos.Line, Column: maxInt(0, pos.Column-1)},
				})
				continue
			}
			imports[alias] = impPath
		}

		loadedFiles = append(loadedFiles, parsedFileRec{
			file:       gf,
			fset:       fset,
			astFile:    astF,
			imports:    imports,
			dotImports: dotImports,
			pkgName:    astF.Name.Name,
		})

		if parsed.PkgSimpleFuncs[gf.ImportPkg] == nil {
			parsed.PkgSimpleFuncs[gf.ImportPkg] = make(map[string]string)
		}
		if parsed.PkgMethods[gf.ImportPkg] == nil {
			parsed.PkgMethods[gf.ImportPkg] = make(map[string]map[string]string)
		}

		for _, decl := range astF.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil {
				continue
			}
			pos := fset.Position(fd.Pos())
			endPos := fset.Position(fd.End())
			endLine := endPos.Line
			loc := &CodeLocation{File: gf.RelPOSIX, Line: pos.Line, Column: maxInt(0, pos.Column-1), EndLine: &endLine}

			recvType := receiverBaseType(fd.Recv)
			var qname, nodeType string
			if recvType != "" {
				qname = gf.ImportPkg + "." + recvType + "." + fd.Name.Name
				nodeType = "method"
				if parsed.PkgMethods[gf.ImportPkg][recvType] == nil {
					parsed.PkgMethods[gf.ImportPkg][recvType] = make(map[string]string)
				}
				parsed.PkgMethods[gf.ImportPkg][recvType][fd.Name.Name] = qname
			} else {
				qname = gf.ImportPkg + "." + fd.Name.Name
				nodeType = "function"
				parsed.PkgSimpleFuncs[gf.ImportPkg][fd.Name.Name] = qname
			}

			if fd.Type != nil && fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
				rt := exprToTypeString(fd.Type.Results.List[0].Type, gf.ImportPkg, imports)
				if rt != "" {
					parsed.FuncReturnTypes[qname] = rt
				}
			}

			parsed.Functions[qname] = &CallGraphNode{
				NodeID:        qname,
				Module:        gf.ImportPkg,
				QualifiedName: qname,
				NodeType:      nodeType,
				IsExternal:    false,
				Location:      loc,
			}

			// Entry point: package main func main()
			if astF.Name.Name == "main" && recvType == "" && fd.Name.Name == "main" {
				addEntryPoint(&parsed, EntryPoint{
					QualifiedName: qname,
					Module:        gf.ImportPkg,
					Source:        "go_main",
					Confidence:    "verified",
					Location:      loc,
				})
			}
		}
	}

	// Pass 2: walk function bodies to track local variable types, HTTP/Cobra entry points, calls, & unresolved dynamic constructs
	for _, lf := range loadedFiles {
		pkgFuncs := parsed.PkgSimpleFuncs[lf.file.ImportPkg]
		for _, decl := range lf.astFile.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || fd.Body == nil {
				continue
			}

			recvType := receiverBaseType(fd.Recv)
			callerID := lf.file.ImportPkg + "." + fd.Name.Name
			if recvType != "" {
				callerID = lf.file.ImportPkg + "." + recvType + "." + fd.Name.Name
			}

			localVars := make(map[string]string)
			funcValVars := make(map[string]bool)

			if fd.Recv != nil {
				for _, fld := range fd.Recv.List {
					rt := exprToTypeString(fld.Type, lf.file.ImportPkg, lf.imports)
					for _, n := range fld.Names {
						localVars[n.Name] = rt
					}
				}
			}
			if fd.Type != nil && fd.Type.Params != nil {
				for _, p := range fd.Type.Params.List {
					pt := exprToTypeString(p.Type, lf.file.ImportPkg, lf.imports)
					for _, n := range p.Names {
						localVars[n.Name] = pt
						if pt == "func" {
							funcValVars[n.Name] = true
						}
					}
				}
			}

			ast.Inspect(fd.Body, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.AssignStmt:
					for idx, lhs := range n.Lhs {
						id, ok := lhs.(*ast.Ident)
						if !ok || idx >= len(n.Rhs) {
							continue
						}
						inferred := inferExprType(n.Rhs[idx], lf.file.ImportPkg, lf.imports, &parsed, localVars)
						if inferred != "" {
							localVars[id.Name] = inferred
							if inferred == "func" {
								funcValVars[id.Name] = true
							}
						}
					}

				case *ast.ValueSpec:
					declT := ""
					if n.Type != nil {
						declT = exprToTypeString(n.Type, lf.file.ImportPkg, lf.imports)
					}
					for idx, name := range n.Names {
						t := declT
						if t == "" && idx < len(n.Values) {
							t = inferExprType(n.Values[idx], lf.file.ImportPkg, lf.imports, &parsed, localVars)
						}
						if t != "" {
							localVars[name.Name] = t
							if t == "func" {
								funcValVars[name.Name] = true
							}
						}
					}

				case *ast.CompositeLit:
					// Detect Cobra cobra.Command{Run: fn, RunE: fn}
					if sel, ok := n.Type.(*ast.SelectorExpr); ok {
						if pkgId, ok := sel.X.(*ast.Ident); ok && strings.HasSuffix(lf.imports[pkgId.Name], "cobra") && sel.Sel.Name == "Command" {
							for _, elt := range n.Elts {
								kv, ok := elt.(*ast.KeyValueExpr)
								if !ok {
									continue
								}
								if k, ok := kv.Key.(*ast.Ident); ok && (k.Name == "Run" || k.Name == "RunE") {
									targetHandler := resolveHandlerExpr(kv.Value, lf.file.ImportPkg, lf.imports, &parsed, callerID)
									if targetHandler != "" {
										pos := lf.fset.Position(kv.Value.Pos())
										addEntryPoint(&parsed, EntryPoint{
											QualifiedName: targetHandler,
											Module:        lf.file.ImportPkg,
											Source:        "go_cobra_command",
											Confidence:    "verified",
											Location:      &CodeLocation{File: lf.file.RelPOSIX, Line: pos.Line, Column: maxInt(0, pos.Column-1)},
										})
									}
								}
							}
						}
					}

				case *ast.CallExpr:
					pos := lf.fset.Position(n.Pos())
					callLoc := CodeLocation{File: lf.file.RelPOSIX, Line: pos.Line, Column: maxInt(0, pos.Column-1)}

					// Record HTTP route registration handlers cleanly
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok && isHTTPRegisterMethod(sel.Sel.Name) && len(n.Args) >= 2 {
						routeStr := ""
						if lit, ok := n.Args[0].(*ast.BasicLit); ok {
							routeStr, _ = strconv.Unquote(lit.Value)
						}
						handlerQ := resolveHandlerExpr(n.Args[len(n.Args)-1], lf.file.ImportPkg, lf.imports, &parsed, callerID)
						if handlerQ != "" {
							modName := lf.file.ImportPkg
							if fnNode := parsed.Functions[handlerQ]; fnNode != nil {
								modName = fnNode.Module
							}
							meta := map[string]string{}
							if routeStr != "" {
								meta["route"] = routeStr
							}
							addEntryPoint(&parsed, EntryPoint{
								QualifiedName: handlerQ,
								Module:        modName,
								Source:        "go_http_handler",
								Confidence:    "verified",
								Location:      &callLoc,
								Metadata:      meta,
							})
							parsed.RawEdges = append(parsed.RawEdges, CallEdgeSite{
								Caller:           callerID,
								Callee:           handlerQ,
								ResolutionMethod: "http_handler_registration",
								Location:         callLoc,
							})
						}
					}

					// Check explicit identifier/selector call targets
					resolveCallExpr(&parsed, n, callerID, lf.file.ImportPkg, lf.imports, pkgFuncs, localVars, funcValVars, callLoc)
				}
				return true
			})
		}
	}

	// Pass 3: Merge explicit entry_points.json rules if provided
	if epConfig != nil {
		for _, rule := range epConfig.EntryPoints {
			cand1 := rule.QualifiedName
			cand2 := rule.Module + "." + rule.QualifiedName
			resolved := ""
			if parsed.Functions[cand1] != nil {
				resolved = cand1
			} else if parsed.Functions[cand2] != nil {
				resolved = cand2
			}
			src := rule.Source
			if src == "" {
				src = "user_config"
			}
			if resolved != "" {
				addEntryPoint(&parsed, EntryPoint{
					QualifiedName: resolved,
					Module:        parsed.Functions[resolved].Module,
					Source:        src,
					Confidence:    "verified",
					Location:      parsed.Functions[resolved].Location,
				})
			} else {
				parsed.EntryPoints = append(parsed.EntryPoints, EntryPoint{
					QualifiedName: rule.QualifiedName,
					Module:        rule.Module,
					Source:        src,
					Confidence:    "unresolved",
				})
				parsed.Diagnostics = append(parsed.Diagnostics, AnalysisDiagnostic{
					Code:     "UNRESOLVED_ENTRY_POINT",
					Severity: "warning",
					Message:  fmt.Sprintf("Configured Go entry point '%s.%s' was not found in repository AST.", rule.Module, rule.QualifiedName),
				})
			}
		}
	}

	sort.Slice(parsed.EntryPoints, func(i, j int) bool {
		if parsed.EntryPoints[i].QualifiedName != parsed.EntryPoints[j].QualifiedName {
			return parsed.EntryPoints[i].QualifiedName < parsed.EntryPoints[j].QualifiedName
		}
		return parsed.EntryPoints[i].Source < parsed.EntryPoints[j].Source
	})

	return parsed
}

func inferExprType(expr ast.Expr, curPkg string, imports map[string]string, parsed *ParsedRepo, localVars map[string]string) string {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return inferExprType(e.X, curPkg, imports, parsed, localVars)
		}
	case *ast.CompositeLit:
		return exprToTypeString(e.Type, curPkg, imports)
	case *ast.FuncLit:
		return "func"
	case *ast.Ident:
		return localVars[e.Name]
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok {
			if id.Name == "new" && len(e.Args) == 1 {
				return exprToTypeString(e.Args[0], curPkg, imports)
			}
			if fnQ, exists := parsed.PkgSimpleFuncs[curPkg][id.Name]; exists {
				return parsed.FuncReturnTypes[fnQ]
			}
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkgId, ok := sel.X.(*ast.Ident); ok {
				if impPath, isImp := imports[pkgId.Name]; isImp {
					if fnQ, exists := parsed.PkgSimpleFuncs[impPath][sel.Sel.Name]; exists {
						return parsed.FuncReturnTypes[fnQ]
					}
					return impPath + "." + sel.Sel.Name
				}
			}
		}
	}
	return ""
}

func resolveHandlerExpr(expr ast.Expr, curPkg string, imports map[string]string, parsed *ParsedRepo, fallbackCaller string) string {
	switch e := expr.(type) {
	case *ast.FuncLit:
		return fallbackCaller
	case *ast.Ident:
		if q, ok := parsed.PkgSimpleFuncs[curPkg][e.Name]; ok {
			return q
		}
	case *ast.SelectorExpr:
		if recv, ok := e.X.(*ast.Ident); ok {
			if impPath, isImp := imports[recv.Name]; isImp {
				if q, ok := parsed.PkgSimpleFuncs[impPath][e.Sel.Name]; ok {
					return q
				}
				return impPath + "." + e.Sel.Name
			}
		}
	}
	return ""
}

func resolveCallExpr(
	parsed *ParsedRepo,
	call *ast.CallExpr,
	callerID string,
	curPkg string,
	imports map[string]string,
	pkgFuncs map[string]string,
	localVars map[string]string,
	funcValVars map[string]bool,
	loc CodeLocation,
) {
	switch fn := call.Fun.(type) {
	case *ast.FuncLit:
		// Anonymous closure executed inline — body statements inspected cleanly inside enclosing callerID!
		return

	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.InterfaceType:
		// Built-in Go type conversions such as []byte(s), any(v), map[K]V(x)
		return

	case *ast.ParenExpr:
		// Handle parenthesized pointer/type conversions such as (*Server)(ptr)
		return

	case *ast.Ident:
		if goBuiltins[fn.Name] {
			return
		}
		if targetQ, ok := pkgFuncs[fn.Name]; ok {
			parsed.RawEdges = append(parsed.RawEdges, CallEdgeSite{
				Caller:           callerID,
				Callee:           targetQ,
				ResolutionMethod: "same_package_direct",
				Location:         loc,
			})
			return
		}
		if funcValVars[fn.Name] || localVars[fn.Name] == "func" {
			parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
				Caller:        callerID,
				RawExpression: exprText(call),
				Category:      "dynamic_func_value_call",
				Reason:        fmt.Sprintf("Invocation of dynamic function value '%s' cannot be resolved statically.", fn.Name),
				Location:      loc,
			})
			return
		}
		// Could be cross-file same-package or dot-import or dynamic global func var
		parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
			Caller:        callerID,
			RawExpression: exprText(call),
			Category:      "unresolved_identifier_call",
			Reason:        fmt.Sprintf("Identifier call '%s' not resolved to declared package function.", fn.Name),
			Location:      loc,
		})

	case *ast.SelectorExpr:
		raw := exprText(call)
		// Check chained reflect.*.MethodByName / .Call
		if isReflectChain(fn, imports) {
			parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
				Caller:        callerID,
				RawExpression: raw,
				Category:      "reflect_dynamic_call",
				Reason:        "Go reflection dispatch (reflect.*) prevents static call-graph resolution.",
				Location:      loc,
			})
			return
		}

		baseIdent, ok := fn.X.(*ast.Ident)
		if !ok {
			// e.g., r.URL.Query() or c.Request.Body — ignore common stdlib HTTP selectors cleanly
			return
		}

		// 1. Package selector call (e.g., yaml.Unmarshal, handlers.Parse, reflect.ValueOf, plugin.Open)
		if impPath, isImport := imports[baseIdent.Name]; isImport {
			if impPath == "reflect" {
				parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
					Caller:        callerID,
					RawExpression: raw,
					Category:      "reflect_dynamic_call",
					Reason:        "Go reflect invocation prevents conservative static reachability guarantee.",
					Location:      loc,
				})
				return
			}
			if impPath == "plugin" && fn.Sel.Name == "Open" {
				parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
					Caller:        callerID,
					RawExpression: raw,
					Category:      "dynamic_plugin_load",
					Reason:        "Dynamic Go plugin.Open loading cannot be statically traced.",
					Location:      loc,
				})
				return
			}

			callee := impPath + "." + fn.Sel.Name
			resMethod := "external_package_call"
			if internalQ, isInternal := parsed.PkgSimpleFuncs[impPath][fn.Sel.Name]; isInternal {
				callee = internalQ
				resMethod = "internal_package_call"
			}
			parsed.RawEdges = append(parsed.RawEdges, CallEdgeSite{
				Caller:           callerID,
				Callee:           callee,
				ResolutionMethod: resMethod,
				Location:         loc,
			})
			return
		}

		// 2. Local receiver variable call (e.g. srv.Handle(), w.Write(), customIface.Run())
		if varType, known := localVars[baseIdent.Name]; known && varType != "" {
			if varType == "interface{}" || varType == "any" {
				parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
					Caller:        callerID,
					RawExpression: raw,
					Category:      "interface_dynamic_dispatch",
					Reason:        fmt.Sprintf("Dynamic interface method invocation '%s.%s' on untyped interface.", baseIdent.Name, fn.Sel.Name),
					Location:      loc,
				})
				return
			}
			pkgPart, typeName := splitQualifiedType(varType, curPkg)
			if typeMethods := parsed.PkgMethods[pkgPart][typeName]; typeMethods != nil {
				if methodNode, exists := typeMethods[fn.Sel.Name]; exists {
					parsed.RawEdges = append(parsed.RawEdges, CallEdgeSite{
						Caller:           callerID,
						Callee:           methodNode,
						ResolutionMethod: "receiver_method_call",
						Location:         loc,
					})
					return
				}
			}
			// Stdlib receiver types (http.ResponseWriter, *http.Request, error, etc.) are safe deterministic edges
			if isKnownStdlibType(pkgPart) || varType == "error" || varType == "string" {
				parsed.RawEdges = append(parsed.RawEdges, CallEdgeSite{
					Caller:           callerID,
					Callee:           varType + "." + fn.Sel.Name,
					ResolutionMethod: "stdlib_method_call",
					Location:         loc,
				})
				return
			}
			// Interface defined outside or unknown concrete implementation
			parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
				Caller:        callerID,
				RawExpression: raw,
				Category:      "interface_dynamic_dispatch",
				Reason:        fmt.Sprintf("Receiver method '%s.%s' on type '%s' has no concrete static target in repository AST.", baseIdent.Name, fn.Sel.Name, varType),
				Location:      loc,
			})
			return
		}

	default:
		// E.g. dynamic slice/map lookup `handlers[key](...)`
		parsed.Unresolved = append(parsed.Unresolved, UnresolvedCall{
			Caller:        callerID,
			RawExpression: exprText(call),
			Category:      "dynamic_computed_call",
			Reason:        "Computed call target expression cannot be determined statically.",
			Location:      loc,
		})
	}
}

func isReflectChain(sel *ast.SelectorExpr, imports map[string]string) bool {
	if sel.Sel.Name == "MethodByName" || sel.Sel.Name == "FieldByName" {
		return true
	}
	cur := sel.X
	for cur != nil {
		switch x := cur.(type) {
		case *ast.Ident:
			return imports[x.Name] == "reflect"
		case *ast.SelectorExpr:
			cur = x.X
		case *ast.CallExpr:
			cur = x.Fun
		default:
			return false
		}
	}
	return false
}

func splitQualifiedType(qualType, defaultPkg string) (string, string) {
	idx := strings.LastIndex(qualType, ".")
	if idx <= 0 {
		return defaultPkg, qualType
	}
	return qualType[:idx], qualType[idx+1:]
}

func isKnownStdlibType(pkgPart string) bool {
	if knownStdlibReceiverPrefixes[pkgPart] {
		return true
	}
	// Check standard library paths like "net/http", "encoding/json", etc.
	if strings.Contains(pkgPart, "/") && !strings.Contains(strings.Split(pkgPart, "/")[0], ".") {
		return true
	}
	return false
}

func addEntryPoint(parsed *ParsedRepo, ep EntryPoint) {
	key := ep.QualifiedName + "|" + ep.Source
	if parsed.EntrySet[key] {
		return
	}
	parsed.EntrySet[key] = true
	parsed.EntryPoints = append(parsed.EntryPoints, ep)
	if node := parsed.Functions[ep.QualifiedName]; node != nil {
		node.IsEntryPoint = true
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
