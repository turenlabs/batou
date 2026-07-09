package scanner

import (
	"testing"
	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-rules/rules"
)

// rxf is a shorthand for a regex finding with just a CWE (uses dedup_test helpers).
func rxf(cwe string) rules.Finding {
	return regexFinding(1, "CWE-"+cwe, rules.High, "medium")
}

// tf is a shorthand for a taint finding with just a CWE.
func tf(cwe string) rules.Finding {
	return taintFinding(1, "CWE-"+cwe, rules.Critical, "high")
}

func TestSuppressRegexWhenTaintClean_ActiveTaint(t *testing.T) {
	// When taint findings exist for a CWE, regex findings for
	// that same CWE should be suppressed.
	findings := []rules.Finding{
		rxf("89"), // SQL injection regex
		tf("89"),  // SQL injection taint
		rxf("327"), // Crypto — not taint-coverable
	}

	result := SuppressRegexWhenTaintClean(findings, nil, "/app/f.go", 0, false)

	// Should keep the taint finding and the crypto regex, drop the SQL regex.
	if len(result) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result))
	}
	for _, f := range result {
		cwe := f.CWEID
		tier := findingTier(&f)
		if cwe == "CWE-89" && tier == tierRegex {
			t.Error("regex SQL injection finding should have been suppressed")
		}
	}
}

func TestSuppressRegexWhenTaintClean_NoTaintNoCache(t *testing.T) {
	// No taint findings and no cache → keep all regex findings.
	findings := []rules.Finding{
		rxf("89"),
		rxf("79"),
	}

	result := SuppressRegexWhenTaintClean(findings, nil, "/app/f.go", 0, false)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (no suppression), got %d", len(result))
	}
}

// TestSuppressRegexWhenTaintClean_UnconfirmableRuleExempt pins the fix for the
// flaky hook-mode suppression: BATOU-NOSQL-001 ($where) detects a shape the
// taint engine structurally cannot model, so a taint-clean negative
// confirmation must NOT suppress it (the regex is the only detection path).
// A different CWE-943 regex rule, which is NOT exempt, is still suppressed.
func TestSuppressRegexWhenTaintClean_UnconfirmableRuleExempt(t *testing.T) {
	nosql001 := regexFinding(1, "CWE-943", rules.High, "medium")
	nosql001.RuleID = "BATOU-NOSQL-001" // exempt — taint can't model object-literal $where
	otherNoSQL := regexFinding(1, "CWE-943", rules.High, "medium")
	otherNoSQL.RuleID = "BATOU-NOSQL-099" // not exempt
	findings := []rules.Finding{nosql001, otherNoSQL}

	// taintRan=true, no taint findings → negativeTaintClean → suppress coverable CWEs.
	result := SuppressRegexWhenTaintClean(findings, nil, "/app/dao.js", 0, true)

	got := map[string]bool{}
	for _, f := range result {
		got[f.RuleID] = true
	}
	if !got["BATOU-NOSQL-001"] {
		t.Error("BATOU-NOSQL-001 must be EXEMPT from taint-clean suppression (taint can't confirm object-literal $where)")
	}
	if got["BATOU-NOSQL-099"] {
		t.Error("a non-exempt CWE-943 regex rule should still be suppressed under negative taint confirmation")
	}
}

func TestSuppressRegexWhenTaintClean_WithinScanTaintRan(t *testing.T) {
	// taintRan=true: the taint engine executed this scan and produced no
	// coverable-CWE finding. Regex-only findings for taint-coverable CWEs
	// are unconfirmed and suppressed WITHOUT a cache entry (the one-shot
	// scan case). Non-coverable CWEs (crypto) are kept.
	findings := []rules.Finding{
		rxf("89"),  // SQLi regex — coverable, taint clean → suppress
		rxf("79"),  // XSS regex  — coverable, taint clean → suppress
		rxf("327"), // Crypto regex — NOT taint-coverable → keep
	}
	result := SuppressRegexWhenTaintClean(findings, nil, "/app/f.go", 0, true)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (only the non-coverable crypto regex), got %d", len(result))
	}
	if result[0].CWEID != "CWE-327" {
		t.Errorf("expected the crypto regex to survive, got %s", result[0].CWEID)
	}
}

func TestSuppressRegexWhenTaintClean_TaintRanKeepsTaintFinding(t *testing.T) {
	// taintRan=true with an active taint finding: the taint TP is kept, the
	// redundant regex twin is suppressed (vuln cases stay detected).
	findings := []rules.Finding{
		rxf("89"), // regex twin
		tf("89"),  // taint TP — must survive
	}
	result := SuppressRegexWhenTaintClean(findings, nil, "/app/f.go", 0, true)
	if len(result) != 1 || findingTier(&result[0]) == tierRegex {
		t.Fatalf("expected only the taint finding to survive, got %d findings", len(result))
	}
}

func TestSuppressRegexWhenTaintClean_NegativeConfirmation(t *testing.T) {
	// Taint ran and found 0 flows (cache entry with matching hash).
	// All regex findings for taint-coverable CWEs should be suppressed.
	content := "package main\nfunc handler() { db.Query(input) }"
	hash := graph.FileContentHash(content)

	cg := graph.NewCallGraph("/project", "s1")
	cg.SetFileTaintCache("/app/handler.go", hash, 0) // 0 flows = clean

	findings := []rules.Finding{
		rxf("89"),  // SQL injection — taint-coverable
		rxf("79"),  // XSS — taint-coverable
		rxf("327"), // Crypto — NOT taint-coverable
	}

	result := SuppressRegexWhenTaintClean(findings, cg, "/app/handler.go", hash, false)

	// Should suppress 89 and 79, keep 327.
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (crypto only), got %d", len(result))
	}
	if result[0].CWEID != "CWE-327" {
		t.Errorf("expected CWE-327 to be kept, got %s", result[0].CWEID)
	}
}

func TestSuppressRegexWhenTaintClean_StaleCache(t *testing.T) {
	// Cache exists but content hash doesn't match (file changed).
	// Should NOT suppress — cache is stale.
	oldHash := graph.FileContentHash("old version")
	newHash := graph.FileContentHash("new version")

	cg := graph.NewCallGraph("/project", "s1")
	cg.SetFileTaintCache("/app/f.go", oldHash, 0)

	findings := []rules.Finding{
		rxf("89"),
	}

	result := SuppressRegexWhenTaintClean(findings, cg, "/app/f.go", newHash, false)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (stale cache, no suppression), got %d", len(result))
	}
}

func TestSuppressRegexWhenTaintClean_CacheWithFlows(t *testing.T) {
	// Cache exists with matching hash but FlowCount > 0.
	// No taint findings in this scan, cache says 3 flows — don't suppress.
	content := "package main\nfunc handler() {}"
	hash := graph.FileContentHash(content)

	cg := graph.NewCallGraph("/project", "s1")
	cg.SetFileTaintCache("/app/f.go", hash, 3) // 3 flows — not clean

	findings := []rules.Finding{
		rxf("89"),
	}

	result := SuppressRegexWhenTaintClean(findings, cg, "/app/f.go", hash, false)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (cache has flows, no suppression), got %d", len(result))
	}
}

func TestSuppressRegexWhenTaintClean_ActiveTaintOverridesCache(t *testing.T) {
	// When taint findings exist, the active-taint path handles suppression
	// regardless of cache state.
	content := "package main"
	hash := graph.FileContentHash(content)

	cg := graph.NewCallGraph("/project", "s1")
	cg.SetFileTaintCache("/app/f.go", hash, 0)

	findings := []rules.Finding{
		rxf("89"),
		tf("89"),
		rxf("79"), // XSS regex — taint didn't find XSS
	}

	result := SuppressRegexWhenTaintClean(findings, cg, "/app/f.go", hash, false)

	// Active taint for CWE-89 suppresses regex-89.
	// CWE-79 is NOT suppressed by active taint (no taint finding for 79).
	// Negative confirmation doesn't apply because taintActiveCWEs is non-empty.
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (taint-89 + regex-79), got %d", len(result))
	}
}

func TestSuppressRegexWhenTaintClean_NilCallGraph(t *testing.T) {
	// Nil call graph should not panic and should keep all findings.
	findings := []rules.Finding{
		rxf("89"),
	}

	result := SuppressRegexWhenTaintClean(findings, nil, "/app/f.go", 12345, false)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding with nil call graph, got %d", len(result))
	}
}
