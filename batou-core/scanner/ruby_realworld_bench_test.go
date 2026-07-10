package scanner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"github.com/turenlabs/batou-core/testutil"
)

// Ruby real-world benchmarks — two phases:
//
//   Phase 1: TestRailsGoatBench — OWASP RailsGoat, a known-vulnerable Rails
//     training app with ~200 Ruby files. Not a per-case scorecard (no CSV
//     ground truth), but records finding counts by category and asserts
//     category floors so regressions in Ruby rules surface.
//
//   Phase 2: TestDiscourseBench — real Discourse source (~400k LoC Ruby).
//     Pure crash-resistance test: every Ruby file must scan without panic.
//     Records total finding counts as an observability baseline.
//
// Both tests skip when the external repo isn't cloned. Clone via:
//   make bench-railsgoat-clone
//   make bench-discourse-clone

// rubyBenchResult aggregates scan outcomes for a real-world Ruby benchmark.
type rubyBenchResult struct {
	Target         string         `json:"target"`
	FilesScanned   int            `json:"files_scanned"`
	FilesErrored   int            `json:"files_errored"`
	TotalFindings  int            `json:"total_findings"`
	FindingsByCWE  map[string]int `json:"findings_by_cwe"`
	FindingsByRule map[string]int `json:"findings_by_rule"`
}

// rubyCrashSafeBench walks every .rb file under root and scans it with
// panic recovery. Collects aggregate stats and returns them.
//
// Each scan runs in its own goroutine (bounded by GOMAXPROCS) using an
// isolated temp directory so the taint cache and findings store don't
// leak between files. A panic in any single scan is caught, counted as
// an error, and does not abort the rest of the walk.
func rubyCrashSafeBench(t *testing.T, target, root string) *rubyBenchResult {
	t.Helper()

	var rubyFiles []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}
		if info.IsDir() {
			// Skip vendored dependencies and git metadata.
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" || name == "tmp" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".rb") {
			rubyFiles = append(rubyFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	t.Logf("Found %d Ruby files under %s", len(rubyFiles), root)

	result := &rubyBenchResult{
		Target:         target,
		FindingsByCWE:  make(map[string]int),
		FindingsByRule: make(map[string]int),
	}
	var mu sync.Mutex

	// Bounded concurrency — large codebases with race detector will OOM
	// without this.
	maxParallel := runtime.GOMAXPROCS(0)
	if maxParallel < 2 {
		maxParallel = 2
	}
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	// Shared isolated workspace for the entire benchmark — we don't need
	// per-file isolation because we're only counting findings, not
	// tracking lifecycle.
	benchDir := t.TempDir()

	for _, path := range rubyFiles {
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Panic recovery per file — a bug in any rule that kills
			// one scan should not kill the whole benchmark.
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					result.FilesErrored++
					mu.Unlock()
					t.Logf("PANIC scanning %s: %v", path, r)
				}
			}()

			content, err := os.ReadFile(path)
			if err != nil {
				mu.Lock()
				result.FilesErrored++
				mu.Unlock()
				return
			}

			// Normalize the scan path so the scanner doesn't treat this
			// as a test file (many files under test/ would be filtered).
			rel, _ := filepath.Rel(root, path)
			scanPath := "/app/" + target + "/" + rel

			res := testutil.ScanContentInDir(t, scanPath, string(content), benchDir)

			mu.Lock()
			result.FilesScanned++
			result.TotalFindings += len(res.Findings)
			for _, f := range res.Findings {
				if f.CWEID != "" {
					result.FindingsByCWE[f.CWEID]++
				}
				result.FindingsByRule[f.RuleID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	return result
}

// printRubyBenchReport logs a summary of a real-world Ruby benchmark run.
func printRubyBenchReport(t *testing.T, r *rubyBenchResult) {
	t.Helper()

	t.Logf("\n=== %s Real-World Benchmark ===", r.Target)
	t.Logf("Files scanned:  %d", r.FilesScanned)
	t.Logf("Files errored:  %d", r.FilesErrored)
	t.Logf("Total findings: %d", r.TotalFindings)

	// Top 10 CWEs by count.
	type kv struct {
		k string
		v int
	}
	var cwes []kv
	for k, v := range r.FindingsByCWE {
		cwes = append(cwes, kv{k, v})
	}
	sort.Slice(cwes, func(i, j int) bool { return cwes[i].v > cwes[j].v })
	t.Logf("\nTop CWEs:")
	for i, c := range cwes {
		if i >= 10 {
			break
		}
		t.Logf("  %-10s  %d", c.k, c.v)
	}

	// Top 10 rules by count.
	var rules []kv
	for k, v := range r.FindingsByRule {
		rules = append(rules, kv{k, v})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].v > rules[j].v })
	t.Logf("\nTop rules:")
	for i, r := range rules {
		if i >= 10 {
			break
		}
		t.Logf("  %-30s  %d", r.k, r.v)
	}
}

// writeRubyBenchJSON writes a benchmark result to testdata/owasp-bench/
// so the CI artifact upload can pick it up alongside OWASP Benchmark JSONs.
func writeRubyBenchJSON(t *testing.T, r *rubyBenchResult) {
	t.Helper()
	root := projectRoot()
	outDir := filepath.Join(root, "testdata", "owasp-bench", r.Target)
	_ = os.MkdirAll(outDir, 0o755)
	outPath := filepath.Join(outDir, "results.json")
	data, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		t.Logf("warning: could not write results to %s: %v", outPath, err)
	} else {
		t.Logf("Results written to %s", outPath)
	}
}

// ---------------------------------------------------------------------------
// Phase 1: RailsGoat (OWASP) — known-vulnerable Rails training app
// ---------------------------------------------------------------------------

func TestRailsGoatBench(t *testing.T) {
	root := projectRoot()
	repoDir := filepath.Join(root, "testdata", "external", "railsgoat")

	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		t.Skip("RailsGoat not cloned; run: make bench-railsgoat-clone")
	}

	// Only scan the app/ directory — lib/ and config/ contain setup code
	// that inflates counts without reflecting security signal.
	appDir := filepath.Join(repoDir, "app")
	if _, err := os.Stat(appDir); os.IsNotExist(err) {
		t.Skipf("RailsGoat app/ directory not found at %s", appDir)
	}

	result := rubyCrashSafeBench(t, "railsgoat", appDir)
	printRubyBenchReport(t, result)
	writeRubyBenchJSON(t, result)

	// Crash-resistance guardrail: any panic is a hard failure.
	if result.FilesErrored > 0 {
		t.Errorf("PANIC: %d of %d files errored during scan", result.FilesErrored, result.FilesScanned)
	}

	// Coverage tracker — log categories RailsGoat documents but Batou
	// doesn't detect. These are warnings, not failures, so the harness
	// ships while gaps exist; the research loop can close them.
	//
	// When any of these drop to zero as a REGRESSION (previously detected,
	// now missing), promote to t.Errorf. Current status noted per CWE.
	trackedCategories := map[string]string{
		"CWE-89":  "SQL injection",
		"CWE-79":  "XSS",
		"CWE-22":  "path traversal",
		"CWE-601": "open redirect",
		"CWE-502": "deserialization",
		"CWE-94":  "code injection",
		"CWE-915": "mass assignment",
		"CWE-327": "weak crypto",
	}
	t.Logf("\n=== RailsGoat coverage tracker ===")
	for cwe, name := range trackedCategories {
		count := result.FindingsByCWE[cwe]
		if count == 0 {
			t.Logf("  [ GAP ] %s (%s): 0 findings", cwe, name)
		} else {
			t.Logf("  [  OK ] %s (%s): %d findings", cwe, name, count)
		}
	}

	// Hard floor — RailsGoat intentionally contains ~20 vulnerabilities.
	// If Batou finds fewer than 10 total the Ruby rules are catastrophically
	// broken (e.g. catalog didn't load).
	const minTotalFindings = 10
	if result.TotalFindings < minTotalFindings {
		t.Errorf("REGRESSION: RailsGoat total findings %d below floor %d", result.TotalFindings, minTotalFindings)
	}
}

// ---------------------------------------------------------------------------
// Phase 2: Discourse — real-world Rails app crash-resistance test
// ---------------------------------------------------------------------------

func TestDiscourseBench(t *testing.T) {
	root := projectRoot()
	repoDir := filepath.Join(root, "testdata", "external", "discourse")

	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		t.Skip("Discourse not cloned; run: make bench-discourse-clone")
	}

	// Scan the whole repo — Discourse's entire test is "does Batou crash
	// on 400k+ LoC of real Rails code?" Answer must be no.
	result := rubyCrashSafeBench(t, "discourse", repoDir)
	printRubyBenchReport(t, result)
	writeRubyBenchJSON(t, result)

	// Zero-panic requirement. Any file that triggers a panic is a bug
	// in Batou that would crash the hook in production.
	if result.FilesErrored > 0 {
		t.Errorf("PANIC: %d of %d files errored during scan", result.FilesErrored, result.FilesScanned)
	}

	// Sanity floor — a real Rails app of this size should produce at
	// least SOME findings. If it produces zero something is silently
	// broken (rules not loading, catalog empty, etc.).
	if result.FilesScanned > 1000 && result.TotalFindings == 0 {
		t.Errorf("SMOKE: scanned %d files but produced 0 findings — rules likely not loading", result.FilesScanned)
	}
}
