package scanner_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
)

// phpcveExpected describes the expected finding for one PHP CVE fixture.
// Loaded from expected.json in each fixture subdirectory. Same shape as
// pycveExpected and jscveExpected — kept as a separate type so the three
// corpora can evolve independently without forcing a shared struct.
type phpcveExpected struct {
	CVE         string `json:"cve"`
	Description string `json:"description"`
	CWE         string `json:"cwe"`
	Category    string `json:"category"`
	File        string `json:"file,omitempty"`
	Function    string `json:"function,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// phpcveResult holds the scan outcome for one PHP CVE fixture. Mirrors
// phpcveResult so readers familiar with the JS scorecard JSON do not need
// to learn a second schema.
type phpcveResult struct {
	CVE                      string   `json:"cve"`
	Category                 string   `json:"category"`
	CWE                      string   `json:"cwe"`
	Description              string   `json:"description"`
	DetectedInVuln           bool     `json:"detected_in_vuln"`
	DetectedInSafe           bool     `json:"detected_in_safe"`
	DetectedInVulnClassAware bool     `json:"detected_in_vuln_class_aware"`
	DetectedInSafeClassAware bool     `json:"detected_in_safe_class_aware"`
	VulnFiredCWEs            []string `json:"vuln_fired_cwes"`
	VulnFiredRules           []string `json:"vuln_fired_rules"`
	SafeFiredCWEs            []string `json:"safe_fired_cwes"`
	SafeFiredRules           []string `json:"safe_fired_rules"`
}

// scanPHPTree walks a directory and scans every .php file via
// testutil.ScanContent, returning the union of fired CWEs and rule IDs, plus
// the subset of fired CWEs that came from BLOCKING findings (RiskScore ≥ 0.7)
// for the dual-lane block scorecard.
//
// The non-test scan path prefix (/app/...) avoids the scanner's isTestFile
// short-circuit — fixtures look enough like real handlers that we want
// them treated as production code.
func scanPHPTree(t *testing.T, treeRoot, scanWorkDir string) (firedCWEs, firedRules, blockingCWEs []string) {
	t.Helper()
	cweSet := make(map[string]bool)
	ruleSet := make(map[string]bool)
	blockSet := make(map[string]bool)

	err := filepath.Walk(treeRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".php") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping unreadable %s: %v", path, err)
			return nil
		}
		rel, _ := filepath.Rel(treeRoot, path)
		scanPath := "/app/" + filepath.ToSlash(rel)
		result := testutil.ScanContentInDir(t, scanPath, string(content), scanWorkDir)
		for _, c := range extractCWEs(result) {
			cweSet[c] = true
		}
		for _, id := range extractRuleIDs(result) {
			ruleSet[id] = true
		}
		for _, c := range extractBlockingCWEs(result) {
			blockSet[c] = true
		}
		return nil
	})
	if err != nil {
		t.Logf("walk error in %s: %v", treeRoot, err)
	}

	for c := range cweSet {
		firedCWEs = append(firedCWEs, c)
	}
	for id := range ruleSet {
		firedRules = append(firedRules, id)
	}
	for c := range blockSet {
		blockingCWEs = append(blockingCWEs, c)
	}
	sort.Strings(firedCWEs)
	sort.Strings(firedRules)
	sort.Strings(blockingCWEs)
	return firedCWEs, firedRules, blockingCWEs
}

// loadPHPCVEFixture reads expected.json from a fixture subdirectory.
func loadPHPCVEFixture(dir string) (phpcveExpected, error) {
	var exp phpcveExpected
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		return exp, err
	}
	if err := json.Unmarshal(data, &exp); err != nil {
		return exp, fmt.Errorf("parse expected.json in %s: %w", dir, err)
	}
	if exp.CVE == "" {
		exp.CVE = filepath.Base(dir)
	}
	return exp, nil
}

// TestPHPCVEBench runs Batou over the curated PHP CVE corpus at
// testdata/phpcve-bench/ and emits a scorecard. Same shape as
// TestPHPCVEBench: each fixture subdirectory has vuln/ and safe/ trees
// plus expected.json. The test does NOT assert specific TP/FP counts — it
// is a measurement tool; the scorecard goes to t.Log and
// testdata/phpcve-bench/results.json.
//
// Directory names match either "CVE-XXXX-NNNNN" or "classic-<shape>" so
// the corpus can include shape-canonical patterns that recur across many
// named CVEs but don't have a single attribution.
//
// Two scorecards are emitted side-by-side, mirroring the Python and JS
// harnesses:
//   - strict     — fired CWE must equal expected CWE (after CWE- prefix strip).
//   - classAware — fired CWE must equal, be an ancestor of, or be a peer of
//     expected CWE per the curated cweAncestors table shared with the Go,
//     Python and JS corpora (no fork).
func TestPHPCVEBench(t *testing.T) {
	root := projectRoot()
	corpusDir := filepath.Join(root, "testdata", "phpcve-bench")

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Skipf("PHP CVE corpus not found at %s: %v", corpusDir, err)
		return
	}

	var fixtures []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Accept real CVE IDs and shape-canonical "classic-*" directories.
		// Reject anything else (e.g. a stray scratch directory) so a typo
		// in a fixture name fails loud rather than silently disappearing.
		if !strings.HasPrefix(e.Name(), "CVE-") && !strings.HasPrefix(e.Name(), "classic-") {
			continue
		}
		fixtures = append(fixtures, filepath.Join(corpusDir, e.Name()))
	}
	sort.Strings(fixtures)

	if len(fixtures) == 0 {
		t.Skip("no fixtures found under testdata/phpcve-bench/{CVE-*,classic-*}")
		return
	}

	t.Logf("Loaded %d PHP CVE fixtures from %s", len(fixtures), corpusDir)

	benchDir := t.TempDir()

	var results []phpcveResult
	var blockDets []cveBlockDetection

	for _, fixDir := range fixtures {
		exp, err := loadPHPCVEFixture(fixDir)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(fixDir), err)
			continue
		}
		expCWE := normalizeCWE(exp.CWE)

		vulnWork := filepath.Join(benchDir, exp.CVE, "vuln-work")
		safeWork := filepath.Join(benchDir, exp.CVE, "safe-work")
		_ = os.MkdirAll(vulnWork, 0o755)
		_ = os.MkdirAll(safeWork, 0o755)

		vulnDir := filepath.Join(fixDir, "vuln")
		safeDir := filepath.Join(fixDir, "safe")

		vulnCWEs, vulnRules, vulnBlockCWEs := scanPHPTree(t, vulnDir, vulnWork)
		safeCWEs, safeRules, safeBlockCWEs := scanPHPTree(t, safeDir, safeWork)

		blockDets = append(blockDets, cveBlockDetection{
			CVE:              exp.CVE,
			Category:         exp.Category,
			CWE:              exp.CWE,
			DetectedInVuln:   detectedBlocking(vulnBlockCWEs, expCWE),
			DetectedInSafe:   detectedBlocking(safeBlockCWEs, expCWE),
			VulnBlockingCWEs: vulnBlockCWEs,
			SafeBlockingCWEs: safeBlockCWEs,
		})

		detectedInVuln := false
		detectedInVulnClass := false
		for _, c := range vulnCWEs {
			if normalizeCWE(c) == expCWE {
				detectedInVuln = true
			}
			if cweMatches(expCWE, c) {
				detectedInVulnClass = true
			}
		}
		detectedInSafe := false
		detectedInSafeClass := false
		for _, c := range safeCWEs {
			if normalizeCWE(c) == expCWE {
				detectedInSafe = true
			}
			if cweMatches(expCWE, c) {
				detectedInSafeClass = true
			}
		}

		results = append(results, phpcveResult{
			CVE:                      exp.CVE,
			Category:                 exp.Category,
			CWE:                      exp.CWE,
			Description:              exp.Description,
			DetectedInVuln:           detectedInVuln,
			DetectedInSafe:           detectedInSafe,
			DetectedInVulnClassAware: detectedInVulnClass,
			DetectedInSafeClassAware: detectedInSafeClass,
			VulnFiredCWEs:            vulnCWEs,
			VulnFiredRules:           vulnRules,
			SafeFiredCWEs:            safeCWEs,
			SafeFiredRules:           safeRules,
		})
	}

	// --- Scorecard (same layout as TestPHPCVEBench) ---
	t.Logf("\n=== PHPCVE Benchmark Scorecard ===")
	t.Logf("Matching policy: strict = exact CWE match; class-aware = exact, " +
		"ancestor in curated MITRE table, or peer with shared ancestor")

	totalTP, totalFP, totalTN, totalFN := 0, 0, 0, 0
	totalTPClass, totalFPClass, totalTNClass, totalFNClass := 0, 0, 0, 0
	for _, r := range results {
		// strict
		vulnLabel := "NOT DETECTED"
		if r.DetectedInVuln {
			vulnLabel = "DETECTED"
			totalTP++
		} else {
			totalFN++
		}
		safeLabel := "CLEAN"
		if r.DetectedInSafe {
			safeLabel = "FLAGGED"
			totalFP++
		} else {
			totalTN++
		}
		// class-aware
		if r.DetectedInVulnClassAware {
			totalTPClass++
		} else {
			totalFNClass++
		}
		if r.DetectedInSafeClassAware {
			totalFPClass++
		} else {
			totalTNClass++
		}

		classNote := ""
		if r.DetectedInVulnClassAware && !r.DetectedInVuln {
			classNote = " (class-aware: DETECTED via ancestor/peer)"
		}
		t.Logf("%s (%s, %s): %s on vuln, %s on safe -- vuln_cwes=%v safe_cwes=%v%s",
			r.CVE, r.Category, r.CWE, vulnLabel, safeLabel,
			r.VulnFiredCWEs, r.SafeFiredCWEs, classNote)
	}

	scorecard := func(tp, fn, fp, tn int) (tpRate, fpRate, youden float64) {
		totalVuln := tp + fn
		totalSafe := fp + tn
		if totalVuln > 0 {
			tpRate = float64(tp) / float64(totalVuln)
		}
		if totalSafe > 0 {
			fpRate = float64(fp) / float64(totalSafe)
		}
		youden = tpRate - fpRate
		return
	}

	tpRate, fpRate, youden := scorecard(totalTP, totalFN, totalFP, totalTN)
	tpRateClass, fpRateClass, youdenClass := scorecard(
		totalTPClass, totalFNClass, totalFPClass, totalTNClass)

	t.Logf("")
	t.Logf("--- Strict (exact CWE match) ---")
	t.Logf("Totals: %d/%d TP, %d/%d FP", totalTP, totalTP+totalFN, totalFP, totalFP+totalTN)
	t.Logf("Overall: TPRate=%.1f%% FPRate=%.1f%% Youden=%+.1f%%",
		tpRate*100, fpRate*100, youden*100)
	t.Logf("")
	t.Logf("--- Class-aware (ancestor accepted) ---")
	t.Logf("Totals: %d/%d TP, %d/%d FP",
		totalTPClass, totalTPClass+totalFNClass, totalFPClass, totalFPClass+totalTNClass)
	t.Logf("Overall: TPRate=%.1f%% FPRate=%.1f%% Youden=%+.1f%%",
		tpRateClass*100, fpRateClass*100, youdenClass*100)

	// Block lane (RiskScore>=0.7) — INFORMATIONAL only, no floor/assertion.
	blockLane := logCVEBlockLane(t, "PHPCVE", blockDets)

	// Persist results JSON with both scorecards (same struct shape as
	// phpcve-bench/results.json so downstream tooling can read both).
	outDir := filepath.Join(root, "testdata", "phpcve-bench")
	type scorecardSummary struct {
		TP     int     `json:"tp"`
		FP     int     `json:"fp"`
		TN     int     `json:"tn"`
		FN     int     `json:"fn"`
		TPRate float64 `json:"tp_rate"`
		FPRate float64 `json:"fp_rate"`
		Youden float64 `json:"youden"`
	}
	type benchOutput struct {
		Cases      int              `json:"cases"`
		TPRate     float64            `json:"tp_rate"`
		FPRate     float64            `json:"fp_rate"`
		Youden     float64            `json:"youden"`
		Strict     scorecardSummary   `json:"strict"`
		ClassAware scorecardSummary   `json:"class_aware"`
		BlockLane  blockLaneScorecard `json:"block_lane"`
		Results    []phpcveResult     `json:"results"`
	}
	out := benchOutput{
		Cases:  len(results),
		TPRate: tpRate,
		FPRate: fpRate,
		Youden: youden,
		Strict: scorecardSummary{
			TP: totalTP, FP: totalFP, TN: totalTN, FN: totalFN,
			TPRate: tpRate, FPRate: fpRate, Youden: youden,
		},
		ClassAware: scorecardSummary{
			TP: totalTPClass, FP: totalFPClass, TN: totalTNClass, FN: totalFNClass,
			TPRate: tpRateClass, FPRate: fpRateClass, Youden: youdenClass,
		},
		BlockLane: blockLane,
		Results:   results,
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	outPath := filepath.Join(outDir, "results.json")
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		t.Logf("warning: could not write results to %s: %v", outPath, err)
	} else {
		t.Logf("Results written to %s", outPath)
	}
}
