package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DependencyIndex indexes Go symbols parsed from explicit dependency source directories or repo vendor/.
type DependencyIndex struct {
	Available       bool
	PkgAliases      map[string]string          // importPath -> package identifier
	DefinedSymbols  map[string]map[string]bool // importPath -> set of Func / Type.Method names
	Diagnostics     []AnalysisDiagnostic
}

// BuildDependencyIndex inspects vendor/ (if present) and depDirs without executing target code.
func BuildDependencyIndex(repoRoot string, depDirs []string) DependencyIndex {
	idx := DependencyIndex{
		PkgAliases:     make(map[string]string),
		DefinedSymbols: make(map[string]map[string]bool),
	}

	var searchRoots []string
	vendorDir := filepath.Join(repoRoot, "vendor")
	if st, err := os.Stat(vendorDir); err == nil && st.IsDir() {
		searchRoots = append(searchRoots, vendorDir)
	}
	for _, d := range depDirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			searchRoots = append(searchRoots, d)
		}
	}
	if len(searchRoots) == 0 {
		return idx
	}
	idx.Available = true

	fset := token.NewFileSet()
	for _, root := range searchRoots {
		// Detect optional module path at root if go.mod exists
		rootMod := ParseGoModModule(filepath.Join(root, "go.mod"))
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, wErr error) error {
			if wErr != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			var impPath string
			if rootMod != "" {
				if relSlash == "." || relSlash == "" {
					impPath = rootMod
				} else {
					impPath = rootMod + "/" + relSlash
				}
			} else {
				impPath = relSlash
			}

			astF, pErr := parser.ParseFile(fset, p, nil, 0)
			if pErr != nil {
				return nil
			}
			idx.PkgAliases[impPath] = astF.Name.Name
			if idx.DefinedSymbols[impPath] == nil {
				idx.DefinedSymbols[impPath] = make(map[string]bool)
			}
			for _, decl := range astF.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil {
					continue
				}
				rt := receiverBaseType(fd.Recv)
				if rt != "" {
					idx.DefinedSymbols[impPath][rt+"."+fd.Name.Name] = true
				} else {
					idx.DefinedSymbols[impPath][fd.Name.Name] = true
				}
			}
			return nil
		})
	}
	return idx
}

// VerifyCandidateSymbol checks if candidate symbol exists in indexed Go dependency AST sources.
func (d *DependencyIndex) VerifyCandidateSymbol(cand CandidateVulnerableSymbol) (string, []AnalysisDiagnostic) {
	if !d.Available {
		return "dependency_source_unavailable", nil
	}
	syms, modFound := d.DefinedSymbols[cand.Module]
	if !modFound {
		return "dependency_source_unavailable", nil
	}

	shortName := strings.TrimPrefix(cand.QualifiedName, cand.Module+".")
	if syms[shortName] {
		return "verified_in_dependency_source", nil
	}

	return "not_found_in_dependency_source", []AnalysisDiagnostic{{
		Code:          "TARGET_SYMBOL_NOT_FOUND",
		Severity:      "warning",
		Message:       fmt.Sprintf("Candidate Go symbol '%s' not present in dependency AST for '%s'.", cand.QualifiedName, cand.Module),
		AffectedScope: cand.Module,
	}}
}
