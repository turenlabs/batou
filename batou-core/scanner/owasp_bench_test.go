package scanner_test

import (
	"encoding/csv"
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

// owaspExpected holds one row from the OWASP expected results CSV.
type owaspExpected struct {
	TestName      string // e.g. "BenchmarkTest00001"
	Category      string // e.g. "pathtraver"
	IsVulnerable  bool   // true = real vulnerability
	CWE           string // e.g. "22"
}

// owaspResult holds the scan outcome for one test case.
type owaspResult struct {
	TestName     string `json:"test_name"`
	Category     string `json:"category"`
	CWE          string `json:"cwe"`
	IsVulnerable bool   `json:"is_vulnerable"`
	Detected     bool   `json:"detected"`
	FiredCWEs    []string `json:"fired_cwes"`
	FiredRules   []string `json:"fired_rules"`
}

// owaspScorecard holds per-category scores.
type owaspScorecard struct {
	Category string  `json:"category"`
	CWE      string  `json:"cwe"`
	TP       int     `json:"tp"`
	FP       int     `json:"fp"`
	TN       int     `json:"tn"`
	FN       int     `json:"fn"`
	TPRate   float64 `json:"tp_rate"`
	FPRate   float64 `json:"fp_rate"`
	Youden   float64 `json:"youden"` // TPRate - FPRate
}

func projectRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func parseExpectedResults(path string) ([]owaspExpected, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	r := csv.NewReader(f)
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var results []owaspExpected
	for _, rec := range records {
		if len(rec) < 4 {
			continue
		}
		results = append(results, owaspExpected{
			TestName:     strings.TrimSpace(rec[0]),
			Category:     strings.TrimSpace(rec[1]),
			IsVulnerable: strings.TrimSpace(rec[2]) == "true",
			CWE:          strings.TrimSpace(rec[3]),
		})
	}
	return results, nil
}

// extractCWEs pulls CWE numbers from findings (strips "CWE-" prefix).
func extractCWEs(result *testutil.ScanResult) []string {
	seen := make(map[string]bool)
	var cwes []string
	for _, f := range result.Findings {
		cwe := f.CWEID
		cwe = strings.TrimPrefix(cwe, "CWE-")
		if cwe != "" && !seen[cwe] {
			seen[cwe] = true
			cwes = append(cwes, cwe)
		}
	}
	return cwes
}

func extractRuleIDs(result *testutil.ScanResult) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, f := range result.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
		}
	}
	return ids
}

func runOWASPBench(t *testing.T, lang, csvPath, testcodeDir, ext string) {
	expected, err := parseExpectedResults(csvPath)
	if err != nil {
		t.Fatalf("failed to parse expected results: %v", err)
	}

	t.Logf("Loaded %d test cases from %s", len(expected), filepath.Base(csvPath))

	// Use an isolated temp directory so the taint cache and findings store
	// don't leak between test cases or between benchmark runs.
	benchDir := t.TempDir()

	var results []owaspResult
	var mu sync.Mutex

	// Run all test cases in parallel subtests.
	t.Run("Cases", func(t *testing.T) {
		for _, exp := range expected {
			exp := exp
			t.Run(exp.TestName, func(t *testing.T) {
				t.Parallel()

				testFile := filepath.Join(testcodeDir, exp.TestName+ext)
				content, err := os.ReadFile(testFile)
				if err != nil {
					t.Skipf("test file not found: %s", testFile)
					return
				}

				// Scan with a non-test path and isolated working directory
				// so each benchmark run has a clean taint cache and findings store.
				scanPath := "/app/owasp/" + exp.TestName + ext
				result := testutil.ScanContentInDir(t, scanPath, string(content), benchDir)

				firedCWEs := extractCWEs(result)
				firedRules := extractRuleIDs(result)

				// Match: any fired CWE matches the expected CWE.
				detected := false
				for _, c := range firedCWEs {
					if c == exp.CWE {
						detected = true
						break
					}
				}

				mu.Lock()
				results = append(results, owaspResult{
					TestName:     exp.TestName,
					Category:     exp.Category,
					CWE:          exp.CWE,
					IsVulnerable: exp.IsVulnerable,
					Detected:     detected,
					FiredCWEs:    firedCWEs,
					FiredRules:   firedRules,
				})
				mu.Unlock()
			})
		}
	})

	// Scorecard phase — runs after all Cases subtests complete.
	t.Run("Scorecard", func(t *testing.T) {
		// Build per-category scorecard.
		type catKey struct {
			Category string
			CWE      string
		}
		catCounts := make(map[catKey]*owaspScorecard)

		for _, r := range results {
			key := catKey{r.Category, r.CWE}
			sc, ok := catCounts[key]
			if !ok {
				sc = &owaspScorecard{Category: r.Category, CWE: r.CWE}
				catCounts[key] = sc
			}

			if r.IsVulnerable {
				if r.Detected {
					sc.TP++
				} else {
					sc.FN++
				}
			} else {
				if r.Detected {
					sc.FP++
				} else {
					sc.TN++
				}
			}
		}

		// Compute rates and sort.
		var scorecards []owaspScorecard
		for _, sc := range catCounts {
			totalVuln := sc.TP + sc.FN
			totalSafe := sc.FP + sc.TN
			if totalVuln > 0 {
				sc.TPRate = float64(sc.TP) / float64(totalVuln)
			}
			if totalSafe > 0 {
				sc.FPRate = float64(sc.FP) / float64(totalSafe)
			}
			sc.Youden = sc.TPRate - sc.FPRate
			scorecards = append(scorecards, *sc)
		}
		sort.Slice(scorecards, func(i, j int) bool {
			return scorecards[i].Category < scorecards[j].Category
		})

		// Print scorecard.
		t.Logf("\n=== OWASP Benchmark Scorecard (%s) ===", lang)
		t.Logf("%-15s %-6s %4s %4s %4s %4s %7s %7s %7s",
			"Category", "CWE", "TP", "FP", "TN", "FN", "TPRate", "FPRate", "Youden")
		t.Logf("%-15s %-6s %4s %4s %4s %4s %7s %7s %7s",
			"---------------", "------", "----", "----", "----", "----", "-------", "-------", "-------")

		totalTP, totalFP, totalTN, totalFN := 0, 0, 0, 0
		for _, sc := range scorecards {
			t.Logf("%-15s %-6s %4d %4d %4d %4d %6.1f%% %6.1f%% %+6.1f%%",
				sc.Category, sc.CWE, sc.TP, sc.FP, sc.TN, sc.FN,
				sc.TPRate*100, sc.FPRate*100, sc.Youden*100)
			totalTP += sc.TP
			totalFP += sc.FP
			totalTN += sc.TN
			totalFN += sc.FN
		}

		totalVuln := totalTP + totalFN
		totalSafe := totalFP + totalTN
		overallTPRate := 0.0
		overallFPRate := 0.0
		if totalVuln > 0 {
			overallTPRate = float64(totalTP) / float64(totalVuln)
		}
		if totalSafe > 0 {
			overallFPRate = float64(totalFP) / float64(totalSafe)
		}
		youden := overallTPRate - overallFPRate

		t.Logf("%-15s %-6s %4d %4d %4d %4d %6.1f%% %6.1f%% %+6.1f%%",
			"TOTAL", "", totalTP, totalFP, totalTN, totalFN,
			overallTPRate*100, overallFPRate*100, youden*100)
		t.Logf("\nTotal cases: %d | Vulnerable: %d | Safe: %d",
			len(results), totalVuln, totalSafe)
		t.Logf("Overall: TPRate=%.1f%% FPRate=%.1f%% Youden=%+.1f%%",
			overallTPRate*100, overallFPRate*100, youden*100)

		// Log FP and FN details for debugging.
		t.Logf("\n=== False Positives ===")
		for _, r := range results {
			if !r.IsVulnerable && r.Detected {
				t.Logf("FP: %s cat=%s cwe=%s rules=%v cwes=%v",
					r.TestName, r.Category, r.CWE, r.FiredRules, r.FiredCWEs)
			}
		}
		t.Logf("\n=== False Negatives ===")
		for _, r := range results {
			if r.IsVulnerable && !r.Detected {
				t.Logf("FN: %s cat=%s cwe=%s rules=%v cwes=%v",
					r.TestName, r.Category, r.CWE, r.FiredRules, r.FiredCWEs)
			}
		}

		// Write results JSON for external consumption.
		root := projectRoot()
		outDir := filepath.Join(root, "testdata", "owasp-bench", lang)
		_ = os.MkdirAll(outDir, 0o755)
		outPath := filepath.Join(outDir, "results.json")

		type benchOutput struct {
			Language   string            `json:"language"`
			Cases      int               `json:"cases"`
			TPRate     float64           `json:"tp_rate"`
			FPRate     float64           `json:"fp_rate"`
			Youden     float64           `json:"youden"`
			Scorecards []owaspScorecard  `json:"scorecards"`
		}
		out := benchOutput{
			Language:   lang,
			Cases:      len(results),
			TPRate:     overallTPRate,
			FPRate:     overallFPRate,
			Youden:     youden,
			Scorecards: scorecards,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			t.Logf("warning: could not write results to %s: %v", outPath, err)
		} else {
			t.Logf("Results written to %s", outPath)
		}
	})
}

func TestOWASPBenchJava(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "external", "BenchmarkJava", "expectedresults-1.2.csv")
	testcodeDir := filepath.Join(root, "testdata", "external", "BenchmarkJava",
		"src", "main", "java", "org", "owasp", "benchmark", "testcode")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("OWASP BenchmarkJava not cloned; run: make bench-owasp-clone")
	}

	runOWASPBench(t, "java", csvPath, testcodeDir, ".java")
}

func TestOWASPBenchPython(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "external", "BenchmarkPython", "expectedresults-0.1.csv")
	testcodeDir := filepath.Join(root, "testdata", "external", "BenchmarkPython", "testcode")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("OWASP BenchmarkPython not cloned; run: make bench-owasp-clone")
	}

	runOWASPBench(t, "python", csvPath, testcodeDir, ".py")
}
