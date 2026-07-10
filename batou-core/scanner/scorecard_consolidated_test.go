package scanner_test

// Consolidated reference-SAST-gap scorecard.
//
// This is pure MEASUREMENT infrastructure (todo #32 of the reference-SAST-gap
// roadmap). It does not touch the taint engine or any analyzer; it only reads
// the result artifacts the existing per-language benches already write and
// folds them into ONE table so that "are we closing the gap to a reference SAST
// tool" is a tracked number per release instead of a vibe.
//
// Why a separate file from scorecard_test.go: that file's
// TestProductSecurityScorecard measures Batou-vs-vanilla intervention on the
// in-tree fixture corpus. This file measures Batou's TPR/FPR against committed
// CVE ground truth and maps it to the reference-SAST gap. Different question,
// different corpus; kept apart for clarity. They share the package's pct/projectRoot.
//
// What it consolidates
// --------------------
//
//   - The six committed, OFFLINE CVE benches — the spine of the scorecard.
//     Each Test<Lang>CVEBench writes testdata/<lang>cve-bench/results.json with
//     a stable shape ({cases, strict:{tp,fp,tn,fn,tp_rate,fp_rate,youden},
//     class_aware:{...}}). Languages: Go, JS/TS, Python, Java, PHP, Ruby.
//     Fixtures are committed in-tree, so these run with no network and no clone.
//
//   - The OWASP Benchmark (Java + Python), OPTIONAL — folded in only if its
//     results.json already exists under testdata/owasp-bench/<lang>/. Running
//     it requires the cloned BenchmarkJava/BenchmarkPython corpora under
//     testdata/external (see `make bench-owasp-clone`); the scorecard never
//     clones anything itself.
//
// Three deliverables, all emitted by `make scorecard`:
//
//  1. One consolidated table: per language | Batou TPR | Batou FPR | corpus |
//     N cases | reference-SAST column.
//  2. A reference-SAST comparison column. The reference SAST tool's officially
//     supported languages are C, C++, C#, Go, Java/Kotlin, JS/TS, Python, Ruby,
//     Rust, Swift. For PHP, Perl, Lua, Groovy, Zig, and Shell, the reference SAST
//     tool has NO analyzer at all — those rows are marked "reference SAST:
//     unsupported", which is itself a headline differentiator for Batou. For the
//     languages the reference SAST tool DOES support, we do NOT fabricate a
//     reference-SAST TPR/FPR: a canonical reference-SAST OWASP-Benchmark
//     scorecard could not be confirmed from a primary source (consistent with
//     tools/bench-compare/SCORECARD.md), and the reference-SAST CLI/SARIF path is
//     out of scope here. Those rows read "supported (no primary-source number)".
//     An honest blank beats a fabricated comparison.
//  3. A corpus GAP-MAP over all 18 supported language slots (17 languages +
//     TypeScript sharing the JS corpus): for each, whether a committed
//     ground-truth corpus exists. Most non-CVE-bench languages have none — that
//     accurate gap-map is the deliverable, because it tells the next release
//     where Batou's numbers are MEASURED vs merely architecture-inferred, and
//     drives future corpus work.
//
// Output: human-readable text via t.Log AND a JSON artifact at
// testdata/scorecard/scorecard.json (so future releases can diff it).
//
// Run it:
//
//	make scorecard            # refresh the six CVE benches, then aggregate
//	make scorecard-offline    # aggregate committed results.json without re-running
//	CGO_ENABLED=1 go test -run TestConsolidatedScorecard ./batou-core/scanner/
//
// By default TestConsolidatedScorecard only AGGREGATES committed results.json
// files, so it is fast and fully offline. `make scorecard` runs the six CVE
// benches first (refreshing those results.json) and then this aggregation.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Shapes of the result artifacts written by the existing benches.
// ---------------------------------------------------------------------------

// cveScorecardBlock mirrors the {tp,fp,tn,fn,tp_rate,fp_rate,youden} block
// written by every Test<Lang>CVEBench under strict/ and class_aware/.
type cveScorecardBlock struct {
	TP     int     `json:"tp"`
	FP     int     `json:"fp"`
	TN     int     `json:"tn"`
	FN     int     `json:"fn"`
	TPRate float64 `json:"tp_rate"`
	FPRate float64 `json:"fp_rate"`
	Youden float64 `json:"youden"`
}

// cveBenchResults mirrors the top-level results.json each CVE bench writes.
type cveBenchResults struct {
	Cases      int               `json:"cases"`
	TPRate     float64           `json:"tp_rate"`
	FPRate     float64           `json:"fp_rate"`
	Youden     float64           `json:"youden"`
	Strict     cveScorecardBlock `json:"strict"`
	ClassAware cveScorecardBlock `json:"class_aware"`
}

// owaspBenchResults mirrors the top-level results.json the OWASP harness writes.
type owaspBenchResults struct {
	Language string  `json:"language"`
	Cases    int     `json:"cases"`
	TPRate   float64 `json:"tp_rate"`
	FPRate   float64 `json:"fp_rate"`
	Youden   float64 `json:"youden"`
}

// ---------------------------------------------------------------------------
// Static knowledge: reference-SAST language support + the Batou languages.
// ---------------------------------------------------------------------------

// refSASTSupportedLang lists the languages the reference SAST tool has a native
// analyzer for, per its official supported-languages documentation (fetched
// 2026-06-02).
//
// The reference SAST tool supports: C, C++, C#, Go, Java (and Kotlin),
// JavaScript (and TypeScript), Python, Ruby, Rust, Swift. It does NOT support
// PHP, Perl, Lua, Groovy, Zig, or Shell — for those Batou is the only
// static-taint option, a headline differentiator.
var refSASTSupportedLang = map[string]bool{
	"go":         true,
	"javascript": true,
	"typescript": true,
	"python":     true,
	"java":       true,
	"kotlin":     true,
	"ruby":       true,
	"c":          true,
	"cpp":        true,
	"csharp":     true,
	"rust":       true,
	"swift":      true,
	// Unsupported by the reference SAST tool (no analyzer): php, perl, lua, groovy, zig, shell.
}

const refSASTSupportSource = "reference SAST tool supported-languages documentation (fetched 2026-06-02)"

// batouLang is one of Batou's supported languages in the gap-map.
type batouLang struct {
	key    string // canonical lower-case key
	label  string // human label for tables
	engine string // which taint engine handles it
}

// allBatouLangs enumerates the languages Batou's taint layer supports
// (CLAUDE.md "Languages Supported" + the tsflow langconfig map, plus Shell
// added in PR #925). The gap-map reports, for each, whether a committed
// ground-truth corpus exists.
var allBatouLangs = []batouLang{
	{"go", "Go", "astflow"},
	{"python", "Python", "tsflow"},
	{"javascript", "JavaScript", "tsflow"},
	{"typescript", "TypeScript", "tsflow"},
	{"java", "Java", "tsflow"},
	{"php", "PHP", "tsflow"},
	{"ruby", "Ruby", "tsflow"},
	{"c", "C", "tsflow"},
	{"cpp", "C++", "tsflow"},
	{"csharp", "C#", "tsflow"},
	{"kotlin", "Kotlin", "tsflow"},
	{"swift", "Swift", "tsflow"},
	{"rust", "Rust", "tsflow"},
	{"perl", "Perl", "tsflow"},
	{"lua", "Lua", "tsflow"},
	{"groovy", "Groovy", "tsflow"},
	{"zig", "Zig", "tsflow"},
	{"shell", "Shell", "tsflow"},
}

// cveBenchDef describes one committed CVE bench (the scorecard spine).
type cveBenchDef struct {
	langKey  string // gap-map key
	label    string // table label
	dir      string // testdata subdir holding results.json
	testName string // go test -run name to refresh it
}

// cveBenchDefs are the six committed, offline CVE benches forming the spine.
var cveBenchDefs = []cveBenchDef{
	{"go", "Go", "gocve-bench", "TestGoCVEBench"},
	{"javascript", "JS/TS", "jscve-bench", "TestJsCVEBench"},
	{"python", "Python", "pycve-bench", "TestPyCVEBench"},
	{"java", "Java", "javacve-bench", "TestJavaCVEBench"},
	{"php", "PHP", "phpcve-bench", "TestPHPCVEBench"},
	{"ruby", "Ruby", "rubycve-bench", "TestRubyCVEBench"},
}

// ---------------------------------------------------------------------------
// Aggregated rows + JSON artifact shape.
// ---------------------------------------------------------------------------

// scRow is one consolidated measurement row in the JSON artifact.
type scRow struct {
	Language      string  `json:"language"`
	Corpus        string  `json:"corpus"`
	Cases         int     `json:"cases"`
	TPRate        float64 `json:"tp_rate"`
	FPRate        float64 `json:"fp_rate"`
	Youden        float64 `json:"youden"`
	Matching      string  `json:"matching"`
	ReferenceSAST string  `json:"reference_sast_comparison"`
}

// scGapRow is one corpus-availability row over all supported languages.
type scGapRow struct {
	Language              string `json:"language"`
	Engine                string `json:"engine"`
	CommittedCorpus       string `json:"committed_corpus"`
	Cases                 int    `json:"cases"`
	Measured              bool   `json:"measured"`
	ReferenceSASTSupports bool   `json:"reference_sast_supports"`
}

// consolidatedScorecardArtifact is the full JSON artifact future releases diff.
type consolidatedScorecardArtifact struct {
	GeneratedNote       string     `json:"generated_note"`
	ReferenceSASTNote   string     `json:"reference_sast_comparison_note"`
	ReferenceSASTSource string     `json:"reference_sast_support_source"`
	CVERows             []scRow    `json:"cve_bench_rows"`
	CVEPooled           scRow      `json:"cve_bench_pooled_totals"`
	OWASPRows           []scRow    `json:"owasp_bench_rows"`
	GapMap              []scGapRow `json:"corpus_gap_map"`
	MeasuredN           int        `json:"languages_with_committed_corpus"`
	TotalLangs          int        `json:"language_slots_total"`
}

// refSASTComparisonCell renders the reference-SAST comparison cell for a
// language. We are deliberately honest: the reference SAST tool either has no
// analyzer (a Batou differentiator), or supports the language but we have no
// primary-source benchmark number to compare against.
func refSASTComparisonCell(langKey string) string {
	if refSASTSupportedLang[langKey] {
		return "supported (no primary-source number)"
	}
	return "UNSUPPORTED (Batou-only)"
}

// fmtPct renders a 0..1 rate as a percentage string. (Distinct name to avoid
// colliding with the package-level pct(int,int) in scorecard_test.go.)
func fmtPct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

// fmtSignedPct renders a signed Youden index as a percentage string.
func fmtSignedPct(v float64) string { return fmt.Sprintf("%+.1f%%", v*100) }

// readCVEBenchResults reads testdata/<dir>/results.json, if present.
func readCVEBenchResults(root, dir string) (*cveBenchResults, bool) {
	p := filepath.Join(root, "testdata", dir, "results.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var r cveBenchResults
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false
	}
	return &r, true
}

// readOWASPBenchResults reads testdata/owasp-bench/<lang>/results.json, if present.
func readOWASPBenchResults(root, lang string) (*owaspBenchResults, bool) {
	p := filepath.Join(root, "testdata", "owasp-bench", lang, "results.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var r owaspBenchResults
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false
	}
	return &r, true
}

// TestConsolidatedScorecard aggregates the existing offline benches into one
// consolidated reference-SAST-gap scorecard and writes a JSON artifact for
// release-over-release diffing. It is a reporting tool, not a gate, so it never
// fails on measurement *content*; it DOES fail if it cannot produce a usable
// scorecard at all (e.g. a CVE corpus is missing), so a broken aggregation is
// visible.
func TestConsolidatedScorecard(t *testing.T) {
	root := projectRoot()

	// --- Spine: the six committed CVE benches ------------------------------
	var cveRows []scRow
	var tTP, tFP, tTN, tFN, tCases int
	casesByLang := map[string]int{}
	for _, b := range cveBenchDefs {
		res, ok := readCVEBenchResults(root, b.dir)
		if !ok {
			t.Errorf("missing CVE bench results: testdata/%s/results.json "+
				"(run `make scorecard` or `make bench-%s`)", b.dir,
				strings.TrimSuffix(b.dir, "cve-bench"))
			continue
		}
		s := res.Strict // strict CWE match = the conservative headline number
		cveRows = append(cveRows, scRow{
			Language:      b.label,
			Corpus:        b.dir,
			Cases:         res.Cases,
			TPRate:        s.TPRate,
			FPRate:        s.FPRate,
			Youden:        s.Youden,
			Matching:      "strict",
			ReferenceSAST: refSASTComparisonCell(b.langKey),
		})
		casesByLang[b.langKey] = res.Cases
		tTP += s.TP
		tFP += s.FP
		tTN += s.TN
		tFN += s.FN
		tCases += res.Cases
	}
	if len(cveRows) == 0 {
		t.Fatal("no CVE bench results found — cannot produce a scorecard. " +
			"Run `make scorecard` to generate them.")
	}

	// Pooled totals across the spine (pooled confusion matrix, so a 5-case
	// corpus does not weigh the same as a 16-case one).
	pooled := scRow{
		Language:      "ALL (pooled)",
		Corpus:        fmt.Sprintf("%d CVE benches", len(cveRows)),
		Cases:         tCases,
		Matching:      "strict",
		ReferenceSAST: "mixed",
	}
	if tTP+tFN > 0 {
		pooled.TPRate = float64(tTP) / float64(tTP+tFN)
	}
	if tFP+tTN > 0 {
		pooled.FPRate = float64(tFP) / float64(tFP+tTN)
	}
	pooled.Youden = pooled.TPRate - pooled.FPRate

	// --- Optional: OWASP Benchmark (only if already produced) --------------
	var owaspRows []scRow
	for _, lang := range []string{"java", "python"} {
		res, ok := readOWASPBenchResults(root, lang)
		if !ok {
			continue
		}
		label := "Java"
		if lang == "python" {
			label = "Python"
		}
		owaspRows = append(owaspRows, scRow{
			Language:      label,
			Corpus:        "owasp-bench/" + lang,
			Cases:         res.Cases,
			TPRate:        res.TPRate,
			FPRate:        res.FPRate,
			Youden:        res.Youden,
			Matching:      "category-cwe",
			ReferenceSAST: refSASTComparisonCell(lang),
		})
	}

	// --- Corpus GAP-MAP over all supported language slots ------------------
	corpusByLang := map[string]cveBenchDef{}
	for _, b := range cveBenchDefs {
		corpusByLang[b.langKey] = b
	}
	var gap []scGapRow
	measured := 0
	for _, l := range allBatouLangs {
		row := scGapRow{
			Language:              l.label,
			Engine:                l.engine,
			CommittedCorpus:       "(none)",
			ReferenceSASTSupports: refSASTSupportedLang[l.key],
		}
		// JS and TS share the jscve corpus; both count as measured.
		corpusKey := l.key
		if l.key == "typescript" {
			corpusKey = "javascript"
		}
		if b, ok := corpusByLang[corpusKey]; ok {
			row.CommittedCorpus = b.dir
			row.Cases = casesByLang[corpusKey]
			row.Measured = true
			measured++
		}
		gap = append(gap, row)
	}

	// --- Assemble + write the JSON artifact --------------------------------
	out := consolidatedScorecardArtifact{
		GeneratedNote: "Batou reference-SAST-gap consolidated scorecard. Spine = six committed " +
			"offline CVE benches (strict CWE match). OWASP rows present only if " +
			"testdata/owasp-bench was generated.",
		ReferenceSASTNote: "Reference-SAST TPR/FPR is intentionally NOT fabricated. For reference-SAST-supported " +
			"languages no primary-source OWASP scorecard was confirmable; for PHP/Perl/Lua/" +
			"Groovy/Zig/Shell the reference SAST tool has no analyzer at all (Batou-only).",
		ReferenceSASTSource: refSASTSupportSource,
		CVERows:             cveRows,
		CVEPooled:           pooled,
		OWASPRows:           owaspRows,
		GapMap:              gap,
		MeasuredN:           measured,
		TotalLangs:          len(allBatouLangs),
	}

	outDir := filepath.Join(root, "testdata", "scorecard")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}
	outPath := filepath.Join(outDir, "scorecard.json")
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal scorecard: %v", err)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", outPath, err)
	}

	emitConsolidatedScorecardText(t, out, outPath)
}

// emitConsolidatedScorecardText prints the consolidated scorecard via t.Log,
// one row per Logf line so it reads cleanly in `go test -v` and CI logs.
func emitConsolidatedScorecardText(t *testing.T, sc consolidatedScorecardArtifact, jsonPath string) {
	t.Helper()

	t.Log("")
	t.Log("==================================================================================")
	t.Log("  BATOU REFERENCE-SAST-GAP CONSOLIDATED SCORECARD")
	t.Log("==================================================================================")
	t.Log("  Spine: six committed, offline CVE benches (strict CWE match).")
	t.Log("  TPR = real vulns caught; FPR = safe code wrongly flagged; Youden = TPR-FPR.")
	t.Log("")

	// Table 1: CVE-bench measured rows + reference-SAST column.
	t.Log("--- Measured: committed CVE benches (offline) ------------------------------------")
	t.Logf("  %-9s | %-13s | %5s | %8s | %8s | %8s | %s",
		"Language", "Corpus", "N", "BatouTPR", "BatouFPR", "Youden", "reference-SAST comparison")
	t.Log("  ----------+---------------+-------+----------+----------+----------+-------------------------------")
	for _, r := range sc.CVERows {
		t.Logf("  %-9s | %-13s | %5d | %8s | %8s | %8s | %s",
			r.Language, r.Corpus, r.Cases, fmtPct(r.TPRate), fmtPct(r.FPRate),
			fmtSignedPct(r.Youden), r.ReferenceSAST)
	}
	t.Log("  ----------+---------------+-------+----------+----------+----------+-------------------------------")
	t.Logf("  %-9s | %-13s | %5d | %8s | %8s | %8s | %s",
		sc.CVEPooled.Language, sc.CVEPooled.Corpus, sc.CVEPooled.Cases, fmtPct(sc.CVEPooled.TPRate),
		fmtPct(sc.CVEPooled.FPRate), fmtSignedPct(sc.CVEPooled.Youden), sc.CVEPooled.ReferenceSAST)
	t.Log("")

	// Table 2: optional OWASP rows.
	if len(sc.OWASPRows) > 0 {
		t.Log("--- Measured: OWASP Benchmark (present on disk) ----------------------------------")
		t.Logf("  %-9s | %-16s | %5s | %8s | %8s | %8s | %s",
			"Language", "Corpus", "N", "BatouTPR", "BatouFPR", "Youden", "reference-SAST comparison")
		t.Log("  ----------+------------------+-------+----------+----------+----------+----------------------------")
		for _, r := range sc.OWASPRows {
			t.Logf("  %-9s | %-16s | %5d | %8s | %8s | %8s | %s",
				r.Language, r.Corpus, r.Cases, fmtPct(r.TPRate), fmtPct(r.FPRate),
				fmtSignedPct(r.Youden), r.ReferenceSAST)
		}
		t.Log("")
	} else {
		t.Log("--- OWASP Benchmark: not present (optional) --------------------------------------")
		t.Log("  Run `make bench-owasp-clone && make bench-owasp` to add Java/Python OWASP rows,")
		t.Log("  then re-run the scorecard. The CVE-bench spine above is fully offline.")
		t.Log("")
	}

	// Table 3: the corpus gap-map over ALL supported language slots.
	t.Log("--- Corpus GAP-MAP: where Batou's numbers are MEASURED vs inferred ---------------")
	t.Logf("  %-11s | %-8s | %-14s | %5s | %-13s | %s",
		"Language", "Engine", "Committed corpus", "N", "Measured?", "ref-SAST?")
	t.Log("  ------------+----------+----------------+-------+---------------+--------------")
	for _, g := range sc.GapMap {
		measured := "no (inferred)"
		if g.Measured {
			measured = "YES"
		}
		cq := "UNSUPPORTED"
		if g.ReferenceSASTSupports {
			cq = "supported"
		}
		t.Logf("  %-11s | %-8s | %-14s | %5d | %-13s | %s",
			g.Language, g.Engine, g.CommittedCorpus, g.Cases, measured, cq)
	}
	t.Log("  ------------+----------+----------------+-------+---------------+--------------")
	t.Logf("  %d of %d supported language slots have a committed ground-truth corpus.",
		sc.MeasuredN, sc.TotalLangs)
	t.Log("")

	// Reference-SAST honesty note + differentiator headline.
	unsupported := refSASTUnsupportedLabels(sc.GapMap)
	t.Log("--- reference-SAST comparison notes ----------------------------------------------")
	t.Logf("  The reference SAST tool has NO analyzer for: %s.", strings.Join(unsupported, ", "))
	t.Log("    -> Batou is the only static-taint option there (headline differentiator).")
	t.Log("  For reference-SAST-supported languages we do NOT print a reference-SAST TPR/FPR: a")
	t.Log("  canonical primary-source reference-SAST OWASP scorecard was not confirmable, and")
	t.Log("  fabricating one would defeat the purpose of a tracked gap number. The reproducible")
	t.Log("  reference-SAST SARIF path lives in tools/bench-compare/ for when its CLI + build env exist.")
	t.Logf("  reference-SAST language-support source: %s", sc.ReferenceSASTSource)
	t.Log("")
	t.Logf("  JSON artifact (diff this across releases): %s", jsonPath)
	t.Log("==================================================================================")
}

// refSASTUnsupportedLabels returns the sorted labels of languages the reference
// SAST tool cannot analyze, from the gap-map.
func refSASTUnsupportedLabels(gap []scGapRow) []string {
	var out []string
	for _, g := range gap {
		if !g.ReferenceSASTSupports {
			out = append(out, g.Language)
		}
	}
	sort.Strings(out)
	return out
}
