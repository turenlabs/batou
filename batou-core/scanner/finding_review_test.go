package scanner

import (
	"fmt"
	"hash/fnv"
	"strings"
	"testing"

	fpfilter "github.com/turenlabs/batou-core/fpfilter"
	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-rules/rules"
)

func fnv1aHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func fmtSprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// ---------------------------------------------------------------------------
// Finding #1 — triple-quoted string handling in countBracketDelta
// ---------------------------------------------------------------------------
//
// Claim being tested: `i = i + 3 + end + 2` overshoots by one byte.
//
// These tests show the claim is WRONG when a triple-quoted string closes
// on the same line. The +2 math is correct: i lands on the last " of the
// closer, then the loop's i++ advances past it.
//
// They also show a SEPARATE real issue: countBracketDelta is stateless,
// so an unclosed triple-quote on one line leaves the next line miscounting
// brackets that actually live inside the string literal.

func TestCountBracketDelta_TripleQuoteClosedSameLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want int
	}{
		{"no brackets before or after", `x = """abc"""`, 0},
		{"open paren after closed triple", `x = """abc""" + (`, 1},
		{"paren wraps triple-quoted", `foo("""bar""")`, 0},
		{"open paren, triple closes, no closing paren", `foo(""" bar """`, 1},
		{"triple at start, paren after", `"""hi""" + (`, 1},
		{"two triple-quoted strings back to back", `a = """x""" + """y""" + (`, 1},
		{"triple-quoted with escaped quote inside", `x = """a\"b""" + (`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := countBracketDelta(tc.line)
			if got != tc.want {
				t.Errorf("countBracketDelta(%q) = %d, want %d", tc.line, got, tc.want)
			}
		})
	}
}

func TestCountBracketDelta_UnclosedTripleQuote_ReturnsEarly(t *testing.T) {
	// When a triple-quote is unclosed on the line, the function bails out
	// with the current delta — it does NOT miscount brackets that appear
	// after the unclosed triple on the same line.
	cases := []struct {
		name string
		line string
		want int
	}{
		{"unclosed triple, no prior brackets", `x = """abc`, 0},
		{"unclosed triple, one open paren before", `foo(x = """abc`, 1},
		// Paren appears after unclosed triple — correctly NOT counted,
		// because it's inside the string that continues to the next line.
		{"unclosed triple, open paren after is ignored", `x = """abc (`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := countBracketDelta(tc.line)
			if got != tc.want {
				t.Errorf("countBracketDelta(%q) = %d, want %d", tc.line, got, tc.want)
			}
		})
	}
}

// TestJoinPython_UnclosedTripleAcrossLines verifies that brackets inside
// a multi-line triple-quoted string are NOT counted against nesting depth.
// Before the fix, line 2's `{` would spuriously open a continuation group.
func TestJoinPython_UnclosedTripleAcrossLines_StatefulTracking(t *testing.T) {
	input := "s = \"\"\"\n" + // line 1: opens triple-quote
		"data = {\n" + // line 2: UNBALANCED `{` INSIDE the string
		"\"\"\"\n" + // line 3: closes triple-quote
		"x = 1\n" // line 4: separate statement

	got, preToOrig := JoinContinuationLinesWithMap(input, rules.LangPython)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")

	// After the fix: lines 1–3 are joined (multi-line docstring), line 4
	// is separate. preToOrig for joined lines should point at their start.
	if len(lines) != 2 {
		t.Fatalf("expected 2 preprocessed lines (docstring + assignment), "+
			"got %d: %q", len(lines), lines)
	}
	// The docstring group spans lines 1–3, starting at line 1.
	if preToOrig[0] != 1 {
		t.Errorf("docstring group should start at orig line 1, got %d", preToOrig[0])
	}
	// `x = 1` is a fresh group starting at line 4.
	if preToOrig[1] != 4 {
		t.Errorf("`x = 1` should map to orig line 4, got %d", preToOrig[1])
	}
	if !strings.Contains(lines[1], "x = 1") {
		t.Errorf("second preprocessed line should be `x = 1`, got %q", lines[1])
	}
}

// TestJoinPython_RealBracketAfterTripleClose verifies that a real bracket
// AFTER the closing triple-quote on the same line IS counted.
func TestJoinPython_RealBracketAfterTripleClose(t *testing.T) {
	input := "x = \"\"\"docs\"\"\" + (\n" + // line 1: closes triple, opens paren
		"    1\n" + // line 2: inside the paren
		")\n" // line 3: closes paren

	got, preToOrig := JoinContinuationLinesWithMap(input, rules.LangPython)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")

	if len(lines) != 1 {
		t.Fatalf("paren continuation should collapse to 1 line, got %d: %q",
			len(lines), lines)
	}
	if preToOrig[0] != 1 {
		t.Errorf("group should start at orig line 1, got %d", preToOrig[0])
	}
}

// TestJoinPython_SingleLineTripleQuoteDoesNotAffectState verifies that a
// closed-on-same-line triple-quoted string doesn't leak state to next lines.
func TestJoinPython_SingleLineTripleQuoteDoesNotAffectState(t *testing.T) {
	input := "a = \"\"\"inline docstring\"\"\"\n" +
		"b = 2\n"

	got, _ := JoinContinuationLinesWithMap(input, rules.LangPython)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")

	if len(lines) != 2 {
		t.Fatalf("closed single-line triple should leave lines independent, "+
			"got %d: %q", len(lines), lines)
	}
}

// TestJoinPython_BalancedBracketsInsideTripleQuote verifies that brackets
// inside a multi-line docstring — balanced or not — are treated as string
// content. The docstring collapses to one preprocessed line regardless.
func TestJoinPython_BalancedBracketsInsideTripleQuote(t *testing.T) {
	input := "x = \"\"\"\n" +
		"if (foo):\n" +
		"\"\"\"\n" +
		"y = 1\n"

	got, preToOrig := JoinContinuationLinesWithMap(input, rules.LangPython)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")

	if len(lines) != 2 {
		t.Fatalf("docstring should collapse into one preprocessed line, got %d: %q",
			len(lines), lines)
	}
	if preToOrig[0] != 1 || preToOrig[1] != 4 {
		t.Errorf("preToOrig = %v, want [1 4]", preToOrig)
	}
	if !strings.Contains(lines[0], `if (foo):`) {
		t.Errorf("docstring content should be preserved in joined line, got %q", lines[0])
	}
}

// ---------------------------------------------------------------------------
// Finding #2 — test-file confidence cap runs after multi-layer boost
// ---------------------------------------------------------------------------
//
// Claim: DeduplicateFindings boosts confidence based on distinct tiers,
// then the test-file block slams confidence down to 0.3, erasing the
// boost. The tier tag is preserved but the numeric confidence no longer
// reflects that multiple layers agreed.
//
// These tests confirm the ordering and its observable effect.

func TestTestFileCap_ErasesMultiLayerBoost(t *testing.T) {
	// Simulate the pipeline order from scanner.go:308-423 for a test file.
	// 1. AssignBaseConfidenceScore (regex=0.5, taint preserves pre-set 0.85)
	// 2. DeduplicateFindings → taint wins, boost for 2 distinct tiers
	// 3. test-file cap: ConfidenceScore > 0.3 → set to 0.3

	regex := rules.Finding{
		RuleID:     "BATOU-INJ-001",
		LineNumber: 42,
		CWEID:      "CWE-89",
		Severity:   rules.High,
		Confidence: "high",
		Tags:       []string{"sql"},
	}
	taint := rules.Finding{
		RuleID:          "BATOU-TAINT-sqli",
		LineNumber:      42,
		CWEID:           "CWE-89",
		Severity:        rules.High,
		Confidence:      "high",
		ConfidenceScore: 0.85,
		Tags:            []string{"taint-analysis", "dataflow"},
	}

	findings := []rules.Finding{regex, taint}

	// Step 1: AssignBaseConfidenceScore (taint score preserved).
	for i := range findings {
		AssignBaseConfidenceScore(&findings[i])
	}
	if findings[0].ConfidenceScore != ConfBaseRegexHigh {
		t.Fatalf("regex base = %v, want %v", findings[0].ConfidenceScore, ConfBaseRegexHigh)
	}
	if findings[1].ConfidenceScore != 0.85 {
		t.Fatalf("taint base should be preserved, got %v", findings[1].ConfidenceScore)
	}

	// Step 2: dedup with multi-layer boost.
	findings = DeduplicateFindings(findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(findings))
	}
	winner := findings[0]
	if winner.RuleID != "BATOU-TAINT-sqli" {
		t.Fatalf("expected taint winner, got %s", winner.RuleID)
	}
	boosted := winner.ConfidenceScore
	if boosted <= 0.85 {
		t.Fatalf("expected boost above 0.85, got %v", boosted)
	}
	t.Logf("after dedup: ConfidenceScore = %.2f (boosted from 0.85)", boosted)
	// Tier evidence in tags survives — this is useful context.
	if !hasTag(winner.Tags, "taint-analysis") {
		t.Error("taint-analysis tag should survive dedup")
	}

	// Step 3: test-file cap (mirrors scanner.go:422-423).
	testPath := "/repo/internal/foo/foo_test.go"
	if !fpfilter.IsTestFile(testPath) {
		t.Fatalf("test setup broken: %q not recognized as test file", testPath)
	}
	if winner.ConfidenceScore > 0.3 {
		winner.ConfidenceScore = 0.3
	}

	// The boost metadata is gone from the score. Tags still say taint-analysis,
	// but SyncConfidenceString will label this as "low".
	if winner.ConfidenceScore != 0.3 {
		t.Fatalf("cap should slam to 0.3, got %v", winner.ConfidenceScore)
	}
	winner.SyncConfidenceString()
	if winner.Confidence != "low" {
		t.Errorf("after cap, Confidence label = %q, expected low", winner.Confidence)
	}
	t.Logf("CONFIRMED: multi-layer boost (%.2f → 0.30) wasted in test files; "+
		"UI shows 'low' despite taint+regex agreement", boosted)
}

// ---------------------------------------------------------------------------
// Finding #5 — SuppressRegexWhenTaintClean / negative-taint confirmation
// ---------------------------------------------------------------------------
//
// taintCoverableCWEs lists CWEs eligible for negative-taint suppression.
// Several of those CWEs originally had NO corresponding SinkCategory in the
// taint engine, so negative confirmation ("taint ran, 0 flows" on a
// hash-matched file) would silently suppress the regex finding on every
// rescan — a false negative. That gap (epic E2) is now closed:
//
//   - CWE-943  (NoSQL injection)              → SnkNoSQL                                  (#639)
//   - CWE-95   (Eval injection)               → aliased to CWE-94 / SnkEval via cweAliases
//   - CWE-1236 (CSV/spreadsheet formula inj.) → SnkCSV                                    (#743)
//   - CWE-73   (external file name/path ctl)  → CWEID "CWE-73" on the SnkFileWrite path-construction sinks (#746)
//   - CWE-434  (unrestricted file upload)     → SnkUpload                                 (#747)
//
// The tests below exercise the negative-confirmation mechanism itself and
// the active-taint path for the formerly-uncovered CWEs (see the
// TestSuppressRegexWhenTaintClean_CWE{1236,73,434}TaintSuppressesRegexTwin
// tests).

// When taint analysis ran on a hash-matched file and recorded 0 flows,
// negative confirmation suppresses regex-only findings for every
// taint-coverable CWE — the file is confirmed clean, so the regex hits are
// false positives. (Here the regex hit is CWE-943, taint-coverable via
// SnkNoSQL.)
func TestSuppressRegexWhenTaintClean_NegativeConfirmationSuppressesRegex(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(1, "CWE-943", rules.High, "medium"),
	}

	// "taint ran on this exact content, found 0 flows" cache entry.
	content := "package main\nfunc handler() { db.Find(input) }"
	hash := fnv1aHash(content)
	cg := graph.NewCallGraph("/tmp", "test-session")
	cg.SetFileTaintCache("/app/nosql.go", hash, 0)

	result := SuppressRegexWhenTaintClean(findings, cg, "/app/nosql.go", hash, false)

	if len(result) != 0 {
		t.Errorf("expected the regex CWE-943 finding to be suppressed by negative confirmation, got %d kept", len(result))
	}
}

// TestSuppressRegexWhenTaintClean_PoisonedCacheDoesNotSuppress: a
// .batou/callgraph.json shipped in a repository can carry a FileTaintCache
// entry with FlowCount==0 and a correct (attacker-computable) FNV content
// hash — but no valid HMAC signature, because it lacks the victim's local
// key. Such a poisoned entry must NOT be trusted for negative-confirmation
// suppression: the real regex finding has to survive. (The legitimate case
// above writes the entry via SetFileTaintCache, which signs it.)
func TestSuppressRegexWhenTaintClean_PoisonedCacheDoesNotSuppress(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(1, "CWE-943", rules.High, "medium"),
	}

	content := "package main\nfunc handler() { db.Find(input) }"
	hash := fnv1aHash(content)
	cg := graph.NewCallGraph("/tmp", "test-session")
	// Simulate an attacker-shipped entry: correct hash, zero flows, NO Sig.
	cg.FileTaintCaches["/app/nosql.go"] = &graph.FileTaintCache{
		ContentHash: hash,
		FlowCount:   0,
	}

	result := SuppressRegexWhenTaintClean(findings, cg, "/app/nosql.go", hash, false)

	if len(result) != 1 {
		t.Errorf("poisoned (unsigned) cache entry must NOT suppress the regex finding; got %d kept, want 1", len(result))
	}
}

// CWE-95 (Eval Injection) is aliased to CWE-94 (Code Injection) so that
// a CWE-94 SnkEval taint finding suppresses a regex CWE-95 twin on the
// same line. Without the alias, exact-CWE matching keeps both.
func TestSuppressRegexWhenTaintClean_CWE95AliasedToCWE94(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(1, "CWE-95", rules.High, "medium"),
		taintFinding(1, "CWE-94", rules.Critical, "high"),
	}

	cg := graph.NewCallGraph("/tmp", "test-session")
	result := SuppressRegexWhenTaintClean(findings, cg, "/app/eval.py", 0, false)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding kept (taint), got %d: %v", len(result), result)
	}
	if !strings.Contains(result[0].RuleID, "TAINT") {
		t.Errorf("expected the taint finding to survive, got %s", result[0].RuleID)
	}
}

// CWE-1236 (CSV/spreadsheet formula injection) now has the SnkCSV sink
// category, so a taint-tier CWE-1236 finding on a line suppresses the
// regex-tier CWE-1236 twin (BATOU-INJ-018) on the same line — the active-
// taint path, exactly like SQL/command injection.
func TestSuppressRegexWhenTaintClean_CWE1236TaintSuppressesRegexTwin(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(1, "CWE-1236", rules.Medium, "medium"),
		taintFinding(1, "CWE-1236", rules.Medium, "high"),
	}

	cg := graph.NewCallGraph("/tmp", "test-session")
	result := SuppressRegexWhenTaintClean(findings, cg, "/app/export.py", 0, false)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding kept (taint), got %d: %v", len(result), result)
	}
	if !strings.Contains(result[0].RuleID, "TAINT") {
		t.Errorf("expected the taint finding to survive, got %s", result[0].RuleID)
	}
}

// CWE-73 (external control of file name or path) now has taint coverage
// via the path-construction file sinks (os.rename / shutil.move /
// fs.rename / Files.move / File.renameTo / FileUtils.mv / ...) extended
// onto the existing SnkFileWrite category with CWEID "CWE-73", so a
// taint-tier CWE-73 finding on a line suppresses the regex-tier CWE-73
// twin on the same line — the active-taint path, exactly like CWE-1236.
func TestSuppressRegexWhenTaintClean_CWE73TaintSuppressesRegexTwin(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(1, "CWE-73", rules.High, "medium"),
		taintFinding(1, "CWE-73", rules.High, "high"),
	}

	cg := graph.NewCallGraph("/tmp", "test-session")
	result := SuppressRegexWhenTaintClean(findings, cg, "/app/files.py", 0, false)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding kept (taint), got %d: %v", len(result), result)
	}
	if !strings.Contains(result[0].RuleID, "TAINT") {
		t.Errorf("expected the taint finding to survive, got %s", result[0].RuleID)
	}
}

// CWE-434 (unrestricted file upload) now has the dedicated SnkUpload sink
// category (#747), so a taint-tier CWE-434 finding on a line suppresses the
// regex-tier CWE-434 twin on the same line — the active-taint path, exactly
// like SQL/command injection.
func TestSuppressRegexWhenTaintClean_CWE434TaintSuppressesRegexTwin(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(1, "CWE-434", rules.High, "medium"),
		taintFinding(1, "CWE-434", rules.High, "high"),
	}

	cg := graph.NewCallGraph("/tmp", "test-session")
	result := SuppressRegexWhenTaintClean(findings, cg, "/app/upload.py", 0, false)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding kept (taint), got %d: %v", len(result), result)
	}
	if !strings.Contains(result[0].RuleID, "TAINT") {
		t.Errorf("expected the taint finding to survive, got %s", result[0].RuleID)
	}
}

// ---------------------------------------------------------------------------
// Finding #7 — Call graph has no size bound, staleness sweep, or eviction
// ---------------------------------------------------------------------------
//
// CallGraph.Nodes and FileTaintCaches are unbounded maps. Adding 10k nodes
// does not trigger any cleanup, staleness check, or LRU eviction. In
// long-lived sessions (CI, repeated edits) the graph grows monotonically.

func TestCallGraph_NoSizeBoundOrEviction(t *testing.T) {
	cg := graph.NewCallGraph("/tmp", "test-session")

	for i := 0; i < 10000; i++ {
		cg.SetFileTaintCache(
			// Unique path each iteration — simulates churn across many files.
			fmtSprintf("/app/file_%d.go", i),
			uint64(i),
			0,
		)
	}

	// There is no public size getter; use the GetFileTaintCache probe to
	// verify every entry we wrote is still present — nothing was evicted.
	alive := 0
	for i := 0; i < 10000; i++ {
		if cg.GetFileTaintCache(fmtSprintf("/app/file_%d.go", i)) != nil {
			alive++
		}
	}
	if alive != 10000 {
		t.Errorf("some entries were evicted (%d alive of 10000) — cleanup policy exists?", alive)
		return
	}
	t.Logf("CONFIRMED: 10000/10000 entries retained, no eviction or size cap")
	t.Logf("  long-lived sessions accumulate unbounded graph state")
}

func TestTestFileCap_NonTestFilePreservesBoost(t *testing.T) {
	// Control: same setup but non-test path — boost survives.
	regex := rules.Finding{
		RuleID: "BATOU-INJ-001", LineNumber: 42, CWEID: "CWE-89",
		Severity: rules.High, Confidence: "high",
	}
	taint := rules.Finding{
		RuleID: "BATOU-TAINT-sqli", LineNumber: 42, CWEID: "CWE-89",
		Severity: rules.High, Confidence: "high", ConfidenceScore: 0.85,
		Tags: []string{"taint-analysis"},
	}
	findings := []rules.Finding{regex, taint}
	for i := range findings {
		AssignBaseConfidenceScore(&findings[i])
	}
	findings = DeduplicateFindings(findings)

	prodPath := "/repo/internal/app/handler.go"
	if fpfilter.IsTestFile(prodPath) {
		t.Fatalf("test setup broken: %q falsely recognized as test file", prodPath)
	}
	// Non-test file skips the cap, so boost is visible.
	if findings[0].ConfidenceScore <= 0.85 {
		t.Errorf("non-test file should keep boost, got %v", findings[0].ConfidenceScore)
	}
}
