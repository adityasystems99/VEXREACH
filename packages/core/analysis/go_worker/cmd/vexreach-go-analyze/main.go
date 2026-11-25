// vexreach-go-analyze runs conservative static Go AST reachability analysis and outputs JSON conforming
// to contracts/analysis_contract.json. It never compiles or executes target repository code.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/adityasystems99/vexreach/packages/core/analysis/go_worker/internal/analyzer"
)

func main() {
	target := flag.String("target", "", "Target Go repository directory or .go file")
	symbolsPath := flag.String("symbols", "", "Path to candidate vulnerable symbol manifest JSON")
	epPath := flag.String("entry-points", "", "Path to optional entry_points.json config")
	depDirsRaw := flag.String("dependency-source", "", "Comma-separated dependency Go source directories")
	maxDepth := flag.Int("max-depth", 15, "Maximum call graph search depth")
	maxPaths := flag.Int("max-paths", 50, "Maximum call paths per target symbol")
	maxFiles := flag.Int("max-files", 5000, "Maximum number of Go source files to inspect")
	maxNodes := flag.Int("max-nodes", 50000, "Maximum call graph nodes")
	maxEdges := flag.Int("max-edges", 200000, "Maximum call graph edges")
	outPath := flag.String("out", "", "Optional output file path (defaults to stdout)")
	flag.Parse()

	if strings.TrimSpace(*target) == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		os.Exit(2)
	}

	var manifest *analyzer.VulnerabilitySymbolManifest
	var manifestSHA string
	if strings.TrimSpace(*symbolsPath) != "" {
		b, err := os.ReadFile(*symbolsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading --symbols: %v\n", err)
			os.Exit(2)
		}
		sum := sha256.Sum256(b)
		manifestSHA = hex.EncodeToString(sum[:])
		var parsedManifest analyzer.VulnerabilitySymbolManifest
		if err := json.Unmarshal(b, &parsedManifest); err != nil {
			fmt.Fprintf(os.Stderr, "error parsing --symbols JSON: %v\n", err)
			os.Exit(2)
		}
		manifest = &parsedManifest
	}

	var epCfg *analyzer.EntryPointConfig
	if strings.TrimSpace(*epPath) != "" {
		b, err := os.ReadFile(*epPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading --entry-points: %v\n", err)
			os.Exit(2)
		}
		var parsedEP analyzer.EntryPointConfig
		if err := json.Unmarshal(b, &parsedEP); err != nil {
			fmt.Fprintf(os.Stderr, "error parsing --entry-points JSON: %v\n", err)
			os.Exit(2)
		}
		epCfg = &parsedEP
	}

	var depDirs []string
	if strings.TrimSpace(*depDirsRaw) != "" {
		for _, d := range strings.Split(*depDirsRaw, ",") {
			if clean := strings.TrimSpace(d); clean != "" {
				depDirs = append(depDirs, clean)
			}
		}
	}

	bundle, err := analyzer.AnalyzeGoRepository(analyzer.Options{
		TargetPath:           *target,
		Manifest:             manifest,
		ManifestSHA256:       manifestSHA,
		EntryPointConfig:     epCfg,
		DependencySourceDirs: depDirs,
		MaxDepth:             *maxDepth,
		MaxPaths:             *maxPaths,
		MaxFiles:             *maxFiles,
		MaxNodes:             *maxNodes,
		MaxEdges:             *maxEdges,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "analysis error: %v\n", err)
		os.Exit(1)
	}

	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(*outPath, payload, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println(string(payload))
}
