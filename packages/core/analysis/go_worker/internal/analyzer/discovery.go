package analyzer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiscoveredGoFile represents a validated, non-symlink Go source file inside the repository root.
type DiscoveredGoFile struct {
	AbsPath   string
	RelPOSIX  string
	RelDir    string
	ImportPkg string
	SizeBytes int64
}

// DiscoverySummary captures discovered Go files, go.mod module root, and snapshot hash.
type DiscoverySummary struct {
	RootDir            string
	ModulePath         string
	Files              []DiscoveredGoFile
	FilesDiscovered    int
	SkippedFiles       int
	SourceSnapshotHash string
	Diagnostics        []AnalysisDiagnostic
	Truncated          bool
}

var ignoredGoDirs = map[string]bool{
	".git":         true,
	".venv":        true,
	"venv":         true,
	"node_modules": true,
	"vendor":       true,
	"testdata":     true,
}

// ParseGoModModule parses the module declaration line from go.mod without executing Go tools.
func ParseGoModModule(goModPath string) string {
	f, err := os.Open(goModPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "module ") {
			mod := strings.TrimSpace(strings.TrimPrefix(line, "module "))
			if idx := strings.Index(mod, "//"); idx >= 0 {
				mod = strings.TrimSpace(mod[:idx])
			}
			return strings.Trim(mod, `"`)
		}
	}
	return ""
}

// DiscoverGoSources safely walks targetPath (never following symlinks) and bounds file counts/sizes.
func DiscoverGoSources(targetPath string, maxFiles int, maxFileBytes int64) (DiscoverySummary, error) {
	if maxFiles <= 0 {
		maxFiles = 5000
	}
	if maxFileBytes <= 0 {
		maxFileBytes = 5 * 1024 * 1024
	}

	info, err := os.Lstat(targetPath)
	if err != nil {
		return DiscoverySummary{}, fmt.Errorf("target path unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return DiscoverySummary{}, fmt.Errorf("target path must not be a symlink: %s", targetPath)
	}

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return DiscoverySummary{}, err
	}

	var rootDir string
	var singleFile string
	if info.IsDir() {
		rootDir = absTarget
	} else {
		if !strings.HasSuffix(absTarget, ".go") {
			return DiscoverySummary{}, fmt.Errorf("target file is not a .go file: %s", targetPath)
		}
		rootDir = filepath.Dir(absTarget)
		singleFile = absTarget
	}

	modulePath := ParseGoModModule(filepath.Join(rootDir, "go.mod"))
	if modulePath == "" {
		modulePath = filepath.Base(rootDir)
	}

	var rawPaths []string
	var diags []AnalysisDiagnostic
	skipped := 0

	if singleFile != "" {
		rawPaths = append(rawPaths, singleFile)
	} else {
		walkErr := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, wErr error) error {
			if wErr != nil {
				diags = append(diags, AnalysisDiagnostic{
					Code:     "WALK_ERROR",
					Severity: "warning",
					Message:  wErr.Error(),
				})
				return nil
			}
			// Never follow symlinks
			linfo, lErr := os.Lstat(path)
			if lErr != nil || (linfo.Mode()&os.ModeSymlink != 0) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				skipped++
				return nil
			}
			if d.IsDir() {
				if path != rootDir && ignoredGoDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			rawPaths = append(rawPaths, path)
			return nil
		})
		if walkErr != nil {
			return DiscoverySummary{}, walkErr
		}
	}

	sort.Strings(rawPaths)

	summary := DiscoverySummary{
		RootDir:         rootDir,
		ModulePath:      modulePath,
		FilesDiscovered: len(rawPaths),
		SkippedFiles:    skipped,
	}

	hasher := sha256.New()
	if modBytes, err := os.ReadFile(filepath.Join(rootDir, "go.mod")); err == nil {
		hasher.Write([]byte("go.mod\x00"))
		hasher.Write(modBytes)
	}

	for _, abs := range rawPaths {
		if len(summary.Files) >= maxFiles {
			summary.Truncated = true
			diags = append(diags, AnalysisDiagnostic{
				Code:          "MAX_FILES_EXCEEDED",
				Severity:      "warning",
				Message:       fmt.Sprintf("Go file limit (%d) exceeded; remaining files skipped cleanly.", maxFiles),
				AffectedScope: "repository",
			})
			break
		}

		st, stErr := os.Stat(abs)
		if stErr != nil {
			skipped++
			continue
		}
		if st.Size() > maxFileBytes {
			skipped++
			rel, _ := filepath.Rel(rootDir, abs)
			diags = append(diags, AnalysisDiagnostic{
				Code:     "FILE_TOO_LARGE",
				Severity: "warning",
				Message:  fmt.Sprintf("Skipped '%s' (%d bytes > %d max bytes).", filepath.ToSlash(rel), st.Size(), maxFileBytes),
			})
			continue
		}

		rel, err := filepath.Rel(rootDir, abs)
		if err != nil {
			continue
		}
		relPOSIX := filepath.ToSlash(rel)
		relDir := filepath.ToSlash(filepath.Dir(rel))
		importPkg := modulePath
		if relDir != "." && relDir != "" {
			importPkg = modulePath + "/" + relDir
		}

		if content, readErr := os.ReadFile(abs); readErr == nil {
			hasher.Write([]byte(relPOSIX))
			hasher.Write([]byte{0})
			hasher.Write(content)
		}

		summary.Files = append(summary.Files, DiscoveredGoFile{
			AbsPath:   abs,
			RelPOSIX:  relPOSIX,
			RelDir:    relDir,
			ImportPkg: importPkg,
			SizeBytes: st.Size(),
		})
	}

	summary.SkippedFiles = skipped
	summary.SourceSnapshotHash = hex.EncodeToString(hasher.Sum(nil))
	summary.Diagnostics = diags
	return summary, nil
}
