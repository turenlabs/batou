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
	TestName     string   `json:"test_name"`
	Category     string   `json:"category"`
	CWE          string   `json:"cwe"`
	IsVulnerable bool     `json:"is_vulnerable"`
	Detected     bool     `json:"detected"`
	// DetectedBlock is the block-lane analogue of Detected: true only when a
	// BLOCKING finding (RiskScore >= 0.7, Finding.ShouldBlock) fired the
	// expected CWE. Report-lane Detected counts every emitted finding (the
	// historical minConf=0 metric); this counts only the ones the hook would
	// actually hard-block. Used by the informational block-lane scorecard.
	DetectedBlock bool     `json:"detected_block"`
	FiredCWEs     []string `json:"fired_cwes"`
	FiredRules    []string `json:"fired_rules"`
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
	return extractCWEsMinConf(result, 0)
}

// extractCWEsMinConf is like extractCWEs but ignores findings whose computed
// ConfidenceScore is below minConf. A gate of 0 counts every finding
// (the historical behaviour, used by all the existing benches). A positive
// gate is used by TestPerlBench to stop counting low-confidence all-tier
// regex noise as a detection — without a gate, a regex-only Critical that
// merely name-matched a dangerous function would be scored as a true
// positive even though the pipeline would only emit it as a hint, not a
// block (RiskScore < 0.7).
func extractCWEsMinConf(result *testutil.ScanResult, minConf float64) []string {
	seen := make(map[string]bool)
	var cwes []string
	for _, f := range result.Findings {
		if minConf > 0 && f.ConfidenceScore < minConf {
			continue
		}
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
	runOWASPBenchMinConf(t, lang, csvPath, testcodeDir, ext, 0)
}

// runOWASPBenchMinConf is runOWASPBench with a confidence gate: findings
// scoring below minConf are not counted toward detection. minConf == 0
// preserves the historical (count-everything) behaviour for all the
// existing language benches; only TestPerlBench passes a positive gate.
func runOWASPBenchMinConf(t *testing.T, lang, csvPath, testcodeDir, ext string, minConf float64) {
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

	// Limit parallelism to avoid OOM on laptops (race detector shadow memory
	// is ~5-10x per goroutine). GOMAXPROCS is a reasonable proxy for available
	// cores; the semaphore keeps peak memory bounded.
	maxParallel := runtime.GOMAXPROCS(0)
	if maxParallel < 2 {
		maxParallel = 2
	}
	sem := make(chan struct{}, maxParallel)

	// Run all test cases in parallel subtests.
	t.Run("Cases", func(t *testing.T) {
		for _, exp := range expected {
			exp := exp
			t.Run(exp.TestName, func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()

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

				firedCWEs := extractCWEsMinConf(result, minConf)
				firedRules := extractRuleIDs(result)
				// Block-lane CWE set: only findings the hook would hard-block
				// (RiskScore >= 0.7). Same expected-CWE match loop below.
				blockingCWEs := extractBlockingCWEs(result)

				// Match: any fired CWE matches the expected CWE.
				detected := false
				for _, c := range firedCWEs {
					if c == exp.CWE {
						detected = true
						break
					}
				}
				// Block-lane match: any BLOCKING CWE matches the expected CWE.
				detectedBlock := false
				for _, c := range blockingCWEs {
					if c == exp.CWE {
						detectedBlock = true
						break
					}
				}

				mu.Lock()
				results = append(results, owaspResult{
					TestName:      exp.TestName,
					Category:      exp.Category,
					CWE:           exp.CWE,
					IsVulnerable:  exp.IsVulnerable,
					Detected:      detected,
					DetectedBlock: detectedBlock,
					FiredCWEs:     firedCWEs,
					FiredRules:    firedRules,
				})
				mu.Unlock()
			})
		}
	})

	// Scorecard phase — runs after all Cases subtests complete.
	t.Run("Scorecard", func(t *testing.T) {
		// Report lane (minConf=0): every emitted finding counts. This is the
		// historical scorecard; its floors are the regression gate (below).
		scorecards, overallTPRate, overallFPRate, youden :=
			owaspScoreAndLog(t, lang, "", results, func(r owaspResult) bool { return r.Detected })

		// Block lane (RiskScore>=0.7, Finding.ShouldBlock): only findings the
		// hook would hard-block. INFORMATIONAL — computed AFTER the report lane
		// in a DISJOINT slice and never fed to the floor loop, so it can never
		// affect the regression gate. Its distinct "Overall (BLOCK lane):"
		// prefix keeps existing greps bound to the report-lane Overall line.
		owaspScoreAndLog(t, lang, "BLOCK", results, func(r owaspResult) bool { return r.DetectedBlock })

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

		// Regression guardrails — per-category TPR floors and FPR ceilings.
		// These values are baselines from 2026-04-09 minus a 5 pt safety
		// margin. They exist to catch large accuracy regressions (e.g.
		// PR #135 dropped cmdi TPR from 84.6% to 30.8% silently). Any
		// change that violates a floor should be investigated before
		// merge. Bump these when the bench legitimately improves.
		floors := owaspFloorsFor(lang)
		if floors != nil {
			for _, sc := range scorecards {
				floor, ok := floors[sc.Category]
				if !ok {
					continue
				}
				if sc.TPRate < floor.MinTPR {
					t.Errorf("REGRESSION: %s TPRate %.1f%% below floor %.1f%% (was %.1f%% on baseline)",
						sc.Category, sc.TPRate*100, floor.MinTPR*100, floor.BaselineTPR*100)
				}
				if sc.FPRate > floor.MaxFPR {
					t.Errorf("REGRESSION: %s FPRate %.1f%% above ceiling %.1f%% (was %.1f%% on baseline)",
						sc.Category, sc.FPRate*100, floor.MaxFPR*100, floor.BaselineFPR*100)
				}
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

// owaspScoreAndLog builds the per-(Category,CWE) scorecard from results using
// the supplied detection predicate, prints the table + an Overall line, and
// returns the sorted scorecards and overall rates. It is called twice per
// language: once for the REPORT lane (detected == r.Detected, minConf=0) whose
// returned scorecards feed the floor gate and results.json, and once for the
// BLOCK lane (detected == r.DetectedBlock, RiskScore>=0.7) which is purely
// informational — its return value is discarded so it can never affect the
// regression gate.
//
// laneName "" is the report lane: it prints the historical header and the
// exact "Overall: TPRate=" prefix that CI/memory tooling greps for. Any other
// laneName (e.g. "BLOCK") prints a distinct header and an
// "Overall (BLOCK lane):" prefix so existing greps stay bound to the report
// lane only.
func owaspScoreAndLog(t *testing.T, lang, laneName string, results []owaspResult,
	detected func(owaspResult) bool) (scorecards []owaspScorecard, overallTPRate, overallFPRate, youden float64) {
	t.Helper()

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

		det := detected(r)
		if r.IsVulnerable {
			if det {
				sc.TP++
			} else {
				sc.FN++
			}
		} else {
			if det {
				sc.FP++
			} else {
				sc.TN++
			}
		}
	}

	// Compute rates and sort.
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

	// Print scorecard. The report lane keeps the historical header verbatim;
	// the block lane gets a distinct header so the two are unambiguous in logs.
	if laneName == "" {
		t.Logf("\n=== OWASP Benchmark Scorecard (%s) ===", lang)
	} else {
		t.Logf("\n=== OWASP Benchmark %s-LANE Scorecard (RiskScore>=0.7) (%s) ===", laneName, lang)
	}
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
	if totalVuln > 0 {
		overallTPRate = float64(totalTP) / float64(totalVuln)
	}
	if totalSafe > 0 {
		overallFPRate = float64(totalFP) / float64(totalSafe)
	}
	youden = overallTPRate - overallFPRate

	t.Logf("%-15s %-6s %4d %4d %4d %4d %6.1f%% %6.1f%% %+6.1f%%",
		"TOTAL", "", totalTP, totalFP, totalTN, totalFN,
		overallTPRate*100, overallFPRate*100, youden*100)
	t.Logf("\nTotal cases: %d | Vulnerable: %d | Safe: %d",
		len(results), totalVuln, totalSafe)
	if laneName == "" {
		// EXACT historical prefix — CI and memory tooling grep "Overall: TPRate=".
		t.Logf("Overall: TPRate=%.1f%% FPRate=%.1f%% Youden=%+.1f%%",
			overallTPRate*100, overallFPRate*100, youden*100)
	} else {
		t.Logf("Overall (%s lane): TPRate=%.1f%% FPRate=%.1f%% Youden=%+.1f%%",
			laneName, overallTPRate*100, overallFPRate*100, youden*100)
	}

	return scorecards, overallTPRate, overallFPRate, youden
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

// owaspFloor holds per-category accuracy guardrails.
// BaselineTPR/BaselineFPR are the measured values at the time of setting.
// MinTPR/MaxFPR are those values with a 5 percentage point safety margin
// so small run-to-run fluctuations don't break CI. Any change that breaks
// these floors should be investigated and explicitly bumped if justified.
type owaspFloor struct {
	MinTPR      float64
	MaxFPR      float64
	BaselineTPR float64
	BaselineFPR float64
}

// owaspFloorsFor returns per-category accuracy floors for the given language,
// or nil if the language has no baseline set. Baselines were captured from
// the 2026-04-09 benchmark run after PR #135 (Python sanitizer additions).
func owaspFloorsFor(lang string) map[string]owaspFloor {
	const margin = 0.05 // 5 percentage points
	mk := func(tpr, fpr float64) owaspFloor {
		minTPR := tpr - margin
		if minTPR < 0 {
			minTPR = 0
		}
		maxFPR := fpr + margin
		if maxFPR > 1 {
			maxFPR = 1
		}
		return owaspFloor{MinTPR: minTPR, MaxFPR: maxFPR, BaselineTPR: tpr, BaselineFPR: fpr}
	}

	switch lang {
	case "java":
		// Baselines from the 2026-06-14 within-scan taint-authority run. Java
		// is in withinScanTaintAuthoritative (scanner/regexenrich.go): when the
		// taint engine runs on a Java file and finds no flow for a taint-
		// coverable CWE, the regex-only match for that CWE is suppressed (the
		// dataflow engine is authoritative for those categories on Java, whose
		// source/sink recall is mature). This deliberately TRADES regex-tier
		// recall for near-zero FPR: per-category TPR drops (regex-only hints
		// for dataflow CWEs no longer count standalone) while FPR collapses,
		// lifting Overall from 94.5/16.8/+77.7 to 91.3/0.2/+91.1 Youden. NOT a
		// benchmark hack — same mechanism cuts regex FPs on real Java code; the
		// blocking lane was already regex-excluded so it is unchanged. The trade
		// is intentional, hence the lowered TPR floors below.
		return map[string]owaspFloor{
			"cmdi":         mk(0.913, 0.000),
			"crypto":       mk(1.000, 0.000),
			"hash":         mk(0.690, 0.000), // deliberately not gamed (see #934)
			"ldapi":        mk(0.889, 0.000),
			"pathtraver":   mk(0.887, 0.000),
			"securecookie": mk(1.000, 0.000),
			"sqli":         mk(0.941, 0.013),
			"trustbound":   mk(0.867, 0.000),
			"weakrand":     mk(1.000, 0.000),
			"xpathi":       mk(0.933, 0.000),
			"xss":          mk(0.894, 0.000),
		}
	case "python":
		// Baselines from the 2026-06-09 de-contamination run (get_safe_value
		// sanitizer special-casing removed). Overall: TPR 98.0%, FPR 5.9%,
		// Youden 92.1%. Per-category floors guard against cmdi-style
		// collapses (PR #135 dropped cmdi TPR 84.6% -> 30.8% silently).
		return map[string]owaspFloor{
			"cmdi":            mk(1.000, 1.000),
			"codeinj":         mk(0.950, 0.000),
			"deserialization": mk(1.000, 0.333),
			"hash":            mk(1.000, 0.000),
			"ldapi":           mk(1.000, 0.154),
			"pathtraver":      mk(0.908, 0.078), // PR-PATHpy: FPR 50.5% -> 7.8%
			"redirect":        mk(1.000, 0.000),
			"securecookie":    mk(1.000, 0.000),
			"sqli":            mk(1.000, 0.000),
			"trustbound":      mk(1.000, 0.105),
			"weakrand":        mk(1.000, 0.000),
			"xpathi":          mk(1.000, 0.037),
			"xss":             mk(0.935, 0.052),
			// xxe baseline raised 0.350 -> 0.400 (7/20 -> 8/20 safe-case FPs) by
			// the inline-source-as-argument soundness fix. BenchmarkTest00017 is
			// `param = urllib.parse.unquote_plus(request.cookies.get(...))` then
			// `xml.dom.minidom.parseString(bar, parser)`: a genuine user-input ->
			// XML-parse flow the engine previously DROPPED because the source was
			// an unbound inline call inside unquote_plus (the exact FN this PR
			// fixes). OWASP labels it safe only because the SAX parser disables
			// entity resolution by default — a parser-config-safety property
			// Batou does not yet model. The new FP is therefore the SAME class as
			// the 7 pre-existing xxe FPs (all BATOU-TAINT-deserialize firing on a
			// safely-configured parser), not a new failure mode. TPR stays 100%.
			"xxe": mk(1.000, 0.400),
		}
	}
	return nil
}
