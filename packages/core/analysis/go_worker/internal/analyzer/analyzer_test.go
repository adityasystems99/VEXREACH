package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempGoRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func makeYAMLManifest(symbolQName string) *VulnerabilitySymbolManifest {
	return &VulnerabilitySymbolManifest{
		ManifestVersion: "1.0",
		Entries: []VulnerabilitySymbolEntry{
			{
				VulnerabilityID: "GO-2022-0999",
				Package: SymbolPackageTarget{
					Ecosystem: "golang",
					Name:      "gopkg.in/yaml.v2",
				},
				Symbols: []CandidateVulnerableSymbol{
					{
						Module:        "gopkg.in/yaml.v2",
						QualifiedName: symbolQName,
						SymbolType:    "function",
						Source:        "curated_advisory_analysis",
						Confidence:    "verified",
					},
				},
			},
		},
	}
}

func TestAnalyzeGoDirectAndHTTPRouterReachability(t *testing.T) {
	repo := writeTempGoRepo(t, map[string]string{
		"go.mod": "module example.com/orders\n\ngo 1.22\n",
		"main.go": `package main

import (
	"net/http"
	"example.com/orders/handlers"
)

func main() {
	http.HandleFunc("/parse", handlers.ParseOrder)
}
`,
		"handlers/parse.go": `package handlers

import (
	"net/http"
	gyaml "gopkg.in/yaml.v2"
)

type Server struct{}

func (s *Server) decode(data []byte) {
	_ = gyaml.Unmarshal(data, nil)
}

func ParseOrder(w http.ResponseWriter, r *http.Request) {
	srv := &Server{}
	srv.decode([]byte("ok"))
	_, _ = w.Write([]byte("done"))
}
`,
	})

	depDir := writeTempGoRepo(t, map[string]string{
		"gopkg.in/yaml.v2/yaml.go": `package yaml
func Unmarshal(in []byte, out any) error { return nil }
`,
	})

	bundle, err := AnalyzeGoRepository(Options{
		TargetPath:           repo,
		Manifest:             makeYAMLManifest("gopkg.in/yaml.v2.Unmarshal"),
		DependencySourceDirs: []string{depDir},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bundle.Report.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(bundle.Report.Results))
	}
	res := bundle.Report.Results[0]
	if res.State != "reachable" {
		t.Fatalf("expected reachable state, got %s (diags=%+v)", res.State, res.Diagnostics)
	}
	if res.Reachable == nil || !*res.Reachable {
		t.Fatalf("expected reachable=true")
	}
	if res.DependencySymbolStatus != "verified_in_dependency_source" {
		t.Fatalf("expected verified_in_dependency_source, got %s", res.DependencySymbolStatus)
	}
	if len(res.Path) < 3 {
		t.Fatalf("expected multi-hop path, got %+v", res.Path)
	}
}

func TestAnalyzeGoNoPathNeverConfusedWithReflectUncertainty(t *testing.T) {
	safeRepo := writeTempGoRepo(t, map[string]string{
		"go.mod": "module example.com/safeapp\n\ngo 1.22\n",
		"main.go": `package main

import (
	"net/http"
)

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("healthy"))
}

func main() {
	http.HandleFunc("/healthz", HealthHandler)
}
`,
		"unused/legacy.go": `package unused

import "gopkg.in/yaml.v2"

func DeadParse(data []byte) {
	_ = yaml.Unmarshal(data, nil)
}
`,
	})

	safeBundle, err := AnalyzeGoRepository(Options{
		TargetPath: safeRepo,
		Manifest:   makeYAMLManifest("gopkg.in/yaml.v2.Unmarshal"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	safeRes := safeBundle.Report.Results[0]
	if safeRes.State != "no_path_within_supported_subset" {
		t.Fatalf("expected no_path_within_supported_subset, got %s (unresolved=%+v)", safeRes.State, safeBundle.Report.UnresolvedCalls)
	}
	if safeRes.Reachable == nil || *safeRes.Reachable {
		t.Fatalf("expected reachable=false")
	}

	reflectRepo := writeTempGoRepo(t, map[string]string{
		"go.mod": "module example.com/dynapp\n\ngo 1.22\n",
		"main.go": `package main

import "reflect"

func dispatch(target any, name string) {
	reflect.ValueOf(target).MethodByName(name).Call(nil)
}

func main() {
	dispatch(nil, "Run")
}
`,
	})
	reflectBundle, err := AnalyzeGoRepository(Options{
		TargetPath: reflectRepo,
		Manifest:   makeYAMLManifest("gopkg.in/yaml.v2.Unmarshal"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dynRes := reflectBundle.Report.Results[0]
	if dynRes.State != "unresolved" {
		t.Fatalf("expected unresolved for reflect call, got %s", dynRes.State)
	}
	if dynRes.Reachable != nil {
		t.Fatalf("expected reachable=nil for unresolved")
	}
}

func TestAnalyzeGoDepthLimitAndAbsentSymbolFailClosed(t *testing.T) {
	repo := writeTempGoRepo(t, map[string]string{
		"go.mod": "module example.com/deep\n\ngo 1.22\n",
		"main.go": `package main

import "gopkg.in/yaml.v2"

func step1() { step2() }
func step2() { step3() }
func step3() { _ = yaml.Unmarshal(nil, nil) }
func main()  { step1() }
`,
	})

	shallow, err := AnalyzeGoRepository(Options{
		TargetPath: repo,
		Manifest:   makeYAMLManifest("gopkg.in/yaml.v2.Unmarshal"),
		MaxDepth:   2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shallow.Report.Results[0].State != "analysis_incomplete" {
		t.Fatalf("expected analysis_incomplete at depth 2, got %s", shallow.Report.Results[0].State)
	}

	depDir := writeTempGoRepo(t, map[string]string{
		"gopkg.in/yaml.v2/yaml.go": `package yaml
func Unmarshal(in []byte, out any) error { return nil }
`,
	})
	absent, err := AnalyzeGoRepository(Options{
		TargetPath:           repo,
		Manifest:             makeYAMLManifest("gopkg.in/yaml.v2.MissingAPI"),
		DependencySourceDirs: []string{depDir},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if absent.Report.Results[0].State != "target_symbol_not_found" {
		t.Fatalf("expected target_symbol_not_found, got %s", absent.Report.Results[0].State)
	}
}
