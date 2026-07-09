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

// gocveExpected describes the expected finding for one CVE fixture.
// Loaded from expected.json in each CVE subdirectory.
type gocveExpected struct {
	CVE         string `json:"cve"`         // e.g. "CVE-2024-24786"
	Description string `json:"description"` // human-readable summary
	CWE         string `json:"cwe"`         // e.g. "CWE-835" (with prefix) or "835"
	Category    string `json:"category"`    // short category label, e.g. "loop", "ssrf", "traversal"
	// File path within vuln/ where the vulnerable pattern lives. Used only for
	// reporting context; the harness scans every .go file under vuln/ and safe/.
	File string `json:"file,omitempty"`
	// Function name in the source where the issue lives. Reporting-only.
	Function string `json:"function,omitempty"`
	// Optional reference URL for documentation.
	Reference string `json:"reference,omitempty"`
}

// gocveResult holds the scan outcome for one CVE fixture.
//
// Two flavors of "detected" are recorded:
//   - Strict: a fired CWE matches the expected CWE exactly (after normalization).
//   - Class-aware: the fired CWE is the expected CWE, an ancestor (parent /
//     grandparent in the MITRE hierarchy), or a peer that shares a common
//     ancestor. See cweAncestors for the curated lookup.
type gocveResult struct {
	CVE                       string   `json:"cve"`
	Category                  string   `json:"category"`
	CWE                       string   `json:"cwe"`
	Description               string   `json:"description"`
	DetectedInVuln            bool     `json:"detected_in_vuln"`
	DetectedInSafe            bool     `json:"detected_in_safe"`
	DetectedInVulnClassAware  bool     `json:"detected_in_vuln_class_aware"`
	DetectedInSafeClassAware  bool     `json:"detected_in_safe_class_aware"`
	VulnFiredCWEs             []string `json:"vuln_fired_cwes"`
	VulnFiredRules            []string `json:"vuln_fired_rules"`
	SafeFiredCWEs             []string `json:"safe_fired_cwes"`
	SafeFiredRules            []string `json:"safe_fired_rules"`
}

// normalizeCWE strips the "CWE-" prefix so "CWE-22" and "22" compare equal.
func normalizeCWE(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "CWE-")
}

// cweAncestors is a curated lookup of CWE ancestor relationships that matter
// most for Go web security. Each key maps to its ancestor CWEs (parents,
// grandparents) in the MITRE hierarchy, sourced from cwe.mitre.org "ChildOf"
// relationships in the Research Concepts view. A handful of "CanPrecede"
// relations from CWE-20 are also included because Batou's regex tier often
// fires CWE-20 ("Improper Input Validation") for downstream issues like XSS
// and path traversal — that is a meaningful family-level signal even when the
// precise child weakness wasn't classified.
//
// Source: https://cwe.mitre.org/data/definitions/{N}.html, Research Concepts
// view (CWE-1000). Verified entries:
//
//	CWE-79  ChildOf CWE-74 → CWE-707. Also CanFollow CWE-20.
//	CWE-78  ChildOf CWE-77 → CWE-74 → CWE-707.
//	CWE-89  ChildOf CWE-943 → CWE-74 → CWE-707.
//	CWE-91  ChildOf CWE-74 → CWE-707.
//	CWE-22  ChildOf CWE-706. Also CanFollow CWE-20.
//	CWE-502 ChildOf CWE-913.
//	CWE-918 ChildOf CWE-441, CWE-610.
//	CWE-444 ChildOf CWE-436.
//	CWE-770 ChildOf CWE-400, CWE-665.
//	CWE-835 ChildOf CWE-834 → CWE-691.
//	CWE-94  ChildOf CWE-913 → CWE-664. Also CanFollow CWE-20.
//	CWE-1336 ChildOf CWE-94 → CWE-913. (Template injection.)
//	CWE-77  ChildOf CWE-74 → CWE-707.
//	CWE-327 ChildOf CWE-693. (Use of broken/risky cryptographic algorithm.)
//
// Keep this table small and focused — its purpose is class-aware credit for
// detecting "something in the right family", not exhaustive CWE bookkeeping.
// Additions are shared across the Go and Python CVE corpora; do not fork.
var cweAncestors = map[string][]string{
	// XSS — Injection family.
	"79": {"74", "707", "20"},
	// OS command injection — Command injection / Injection family.
	"78": {"77", "74", "707"},
	// Command injection (generic) — Injection family.
	"77": {"74", "707"},
	// SQL injection — Data-query injection / Injection family.
	"89": {"943", "74", "707"},
	// XML injection — Injection family.
	"91": {"74", "707"},
	// Code injection — Dynamically-managed code resources.
	"94": {"913", "664", "20"},
	// Template injection — Code injection / Dynamically-managed code.
	"1336": {"94", "913", "664"},
	// Path traversal — Use of incorrectly-resolved name.
	"22": {"706", "20"},
	// Deserialization of untrusted data.
	"502": {"913"},
	// SSRF — Confused deputy / externally controlled reference.
	"918": {"441", "610"},
	// HTTP request smuggling — Interpretation conflict.
	"444": {"436"},
	// Resource allocation without limits — Uncontrolled resource consumption.
	"770": {"400", "665"},
	// Infinite loop — Excessive iteration / Improper control flow.
	"835": {"834", "691"},
	// Use of broken or risky cryptographic algorithm — Protection mechanism failure.
	"327": {"693"},
	// XXE — improper restriction of XML external entity reference.
	// ChildOf CWE-610 (externally controlled reference) and CanFollow CWE-20.
	"611": {"610", "20"},
	// JNDI / expression-language injection (Log4Shell family).
	// ChildOf CWE-74 -> CWE-707; closely related to CWE-94 code injection.
	"917": {"74", "707", "94"},
	// Prototype pollution — improper control of object prototype modification.
	// ChildOf CWE-915 -> CWE-913 (improperly controlled modification of dynamically-determined object attributes).
	"1321": {"915", "913"},
}

// cweAncestorSet returns expected ∪ ancestors(expected) for set-membership
// tests. Keys are normalized (no "CWE-" prefix).
func cweAncestorSet(expected string) map[string]bool {
	set := map[string]bool{expected: true}
	for _, anc := range cweAncestors[expected] {
		set[anc] = true
	}
	return set
}

// cweMatches reports whether `detected` should be credited for `expected`
// under class-aware scoring. It returns true when:
//   - detected == expected (exact match), OR
//   - detected is an ancestor of expected in cweAncestors, OR
//   - detected and expected share a common ancestor in cweAncestors
//     (peer classes — e.g. CWE-78 and CWE-89 both descend from CWE-74).
//
// Both inputs may carry the "CWE-" prefix; it is stripped before comparison.
// Unknown CWEs (not in the lookup) only match on exact equality.
func cweMatches(expected, detected string) bool {
	e := normalizeCWE(expected)
	d := normalizeCWE(detected)
	if e == "" || d == "" {
		return false
	}
	if e == d {
		return true
	}
	// Detected is an ancestor of expected.
	if cweAncestorSet(e)[d] {
		return true
	}
	// Expected is an ancestor of detected (less useful for SAST but cheap).
	if cweAncestorSet(d)[e] {
		return true
	}
	// Peer relationship: shared ancestor.
	eAnc := cweAncestorSet(e)
	for anc := range cweAncestorSet(d) {
		if anc == d || anc == e {
			continue
		}
		if eAnc[anc] {
			return true
		}
	}
	return false
}

// scanGoTree walks a directory and scans every .go file via testutil.ScanContent,
// returning the union of fired CWEs and rule IDs across the tree, plus the
// subset of fired CWEs that came from BLOCKING findings (RiskScore ≥ 0.7) for
// the dual-lane block scorecard.
func scanGoTree(t *testing.T, treeRoot, scanWorkDir string) (firedCWEs, firedRules, blockingCWEs []string) {
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping unreadable %s: %v", path, err)
			return nil
		}
		// Use a non-test path with /app/ prefix so isTestFile() doesn't kick in.
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

// loadGoCVEFixture reads expected.json from a CVE subdirectory.
func loadGoCVEFixture(dir string) (gocveExpected, error) {
	var exp gocveExpected
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		return exp, err
	}
	if err := json.Unmarshal(data, &exp); err != nil {
		return exp, fmt.Errorf("parse expected.json in %s: %w", dir, err)
	}
	if exp.CVE == "" {
		// Fall back to directory name.
		exp.CVE = filepath.Base(dir)
	}
	return exp, nil
}

// TestGoCVEBench runs Batou over the curated Go CVE corpus at
// testdata/gocve-bench/ and emits a scorecard. Each CVE subdirectory must
// contain vuln/ and safe/ trees plus an expected.json describing the expected
// CWE. The test does NOT assert specific TP/FP counts — those numbers shift
// as detection improves. It is a measurement tool; the scorecard goes to
// t.Log and testdata/gocve-bench/results.json.
func TestGoCVEBench(t *testing.T) {
	root := projectRoot()
	corpusDir := filepath.Join(root, "testdata", "gocve-bench")

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Skipf("Go CVE corpus not found at %s: %v", corpusDir, err)
		return
	}

	var fixtures []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Skip anything that doesn't look like a CVE directory.
		if !strings.HasPrefix(e.Name(), "CVE-") {
			continue
		}
		fixtures = append(fixtures, filepath.Join(corpusDir, e.Name()))
	}
	sort.Strings(fixtures)

	if len(fixtures) == 0 {
		t.Skip("no CVE fixtures found under testdata/gocve-bench/CVE-*")
		return
	}

	t.Logf("Loaded %d Go CVE fixtures from %s", len(fixtures), corpusDir)

	// Isolated work dir so taint cache / findings store don't leak across CVEs.
	benchDir := t.TempDir()

	var results []gocveResult
	var blockDets []cveBlockDetection

	for _, fixDir := range fixtures {
		exp, err := loadGoCVEFixture(fixDir)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(fixDir), err)
			continue
		}
		expCWE := normalizeCWE(exp.CWE)

		// Each CVE gets its own scratch subdir so cross-file caches don't bleed.
		vulnWork := filepath.Join(benchDir, exp.CVE, "vuln-work")
		safeWork := filepath.Join(benchDir, exp.CVE, "safe-work")
		_ = os.MkdirAll(vulnWork, 0o755)
		_ = os.MkdirAll(safeWork, 0o755)

		vulnDir := filepath.Join(fixDir, "vuln")
		safeDir := filepath.Join(fixDir, "safe")

		vulnCWEs, vulnRules, vulnBlockCWEs := scanGoTree(t, vulnDir, vulnWork)
		safeCWEs, safeRules, safeBlockCWEs := scanGoTree(t, safeDir, safeWork)

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

		results = append(results, gocveResult{
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

	// --- Scorecard ---
	// We compute two scorecards side-by-side:
	//   strict     — fired CWE must equal expected CWE (after CWE- prefix strip).
	//   classAware — fired CWE must equal, be an ancestor of, or be a peer of
	//                expected CWE per the curated cweAncestors table.
	// Strict shows precision of CWE classification; class-aware shows whether
	// we found "something in the right family" — useful when Batou fires a
	// parent class (e.g. CWE-20) for a more specific weakness (e.g. CWE-79).
	t.Logf("\n=== GoCVE Benchmark Scorecard ===")
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

		// Annotate per-case lines with the class-aware verdict so readers can
		// see which CVEs flipped from NOT DETECTED → DETECTED (class).
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
	blockLane := logCVEBlockLane(t, "GoCVE", blockDets)

	// Persist results JSON with both scorecards.
	outDir := filepath.Join(root, "testdata", "gocve-bench")
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
		Cases int `json:"cases"`
		// Strict scorecard (kept as top-level tp_rate/fp_rate/youden for
		// backward compatibility with existing readers of results.json).
		TPRate     float64            `json:"tp_rate"`
		FPRate     float64            `json:"fp_rate"`
		Youden     float64            `json:"youden"`
		Strict     scorecardSummary   `json:"strict"`
		ClassAware scorecardSummary   `json:"class_aware"`
		BlockLane  blockLaneScorecard `json:"block_lane"`
		Results    []gocveResult      `json:"results"`
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
