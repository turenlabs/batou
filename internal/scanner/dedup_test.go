package scanner

import (
	"testing"

	"github.com/turenio/gtss/internal/rules"
)

// helpers to build findings concisely in tests.

func regexFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "GTSS-INJ-001",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       tags,
	}
}

func astFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "GTSS-AST-002",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       append([]string{"ast"}, tags...),
	}
}

func taintFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "GTSS-TAINT-sqli",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       append([]string{"taint-analysis", "dataflow"}, tags...),
	}
}

func interprocFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "GTSS-INTERPROC-SQLI",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       append([]string{"interprocedural", "taint-analysis", "cross-function"}, tags...),
	}
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func TestDedup_TaintWinsOverRegex(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(10, "CWE-89", rules.High, "medium", "sql"),
		taintFinding(10, "CWE-89", rules.High, "high", "sql"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-TAINT-sqli" {
		t.Errorf("expected taint winner, got %s", got[0].RuleID)
	}
	// Regex tags should be merged.
	if !hasTag(got[0].Tags, "sql") {
		t.Error("expected merged tag 'sql' from regex finding")
	}
}

func TestDedup_TaintWinsOverAST(t *testing.T) {
	findings := []rules.Finding{
		astFinding(15, "CWE-89", rules.High, "high"),
		taintFinding(15, "CWE-89", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-TAINT-sqli" {
		t.Errorf("expected taint winner, got %s", got[0].RuleID)
	}
	// AST tag should be merged into the winner.
	if !hasTag(got[0].Tags, "ast") {
		t.Error("expected merged tag 'ast' from AST finding")
	}
}

func TestDedup_ASTWinsOverRegex(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(20, "CWE-79", rules.High, "medium"),
		astFinding(20, "CWE-79", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-AST-002" {
		t.Errorf("expected AST winner, got %s", got[0].RuleID)
	}
}

func TestDedup_ThreeWay(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(5, "CWE-89", rules.Medium, "low"),
		astFinding(5, "CWE-89", rules.High, "medium"),
		taintFinding(5, "CWE-89", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-TAINT-sqli" {
		t.Errorf("expected taint winner, got %s", got[0].RuleID)
	}
	// All tags should be merged.
	if !hasTag(got[0].Tags, "ast") {
		t.Error("expected merged 'ast' tag")
	}
}

func TestDedup_DifferentLinesSurvive(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(10, "CWE-89", rules.High, "high"),
		regexFinding(20, "CWE-89", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (different lines), got %d", len(got))
	}
}

func TestDedup_DifferentCWEsSurvive(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(10, "CWE-89", rules.High, "high"),
		regexFinding(10, "CWE-79", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (different CWEs), got %d", len(got))
	}
}

func TestDedup_MissingCWENotGrouped(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(10, "", rules.High, "high"),
		taintFinding(10, "", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (no CWE), got %d", len(got))
	}
}

func TestDedup_MissingLineNotGrouped(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(0, "CWE-89", rules.High, "high"),
		taintFinding(0, "CWE-89", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (no line number), got %d", len(got))
	}
}

func TestDedup_SameTierSeverityTiebreak(t *testing.T) {
	high := rules.Finding{
		RuleID:     "GTSS-INJ-001",
		LineNumber: 10,
		CWEID:      "CWE-89",
		Severity:   rules.High,
		Confidence: "medium",
		Tags:       []string{"winner"},
	}
	medium := rules.Finding{
		RuleID:     "GTSS-INJ-002",
		LineNumber: 10,
		CWEID:      "CWE-89",
		Severity:   rules.Medium,
		Confidence: "high",
		Tags:       []string{"loser"},
	}
	got := DeduplicateFindings([]rules.Finding{medium, high})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-INJ-001" {
		t.Errorf("expected higher-severity winner GTSS-INJ-001, got %s", got[0].RuleID)
	}
	if !hasTag(got[0].Tags, "loser") {
		t.Error("expected merged tag 'loser' from suppressed finding")
	}
}

func TestDedup_SameTierConfidenceTiebreak(t *testing.T) {
	highConf := rules.Finding{
		RuleID:     "GTSS-INJ-001",
		LineNumber: 10,
		CWEID:      "CWE-89",
		Severity:   rules.High,
		Confidence: "high",
		Tags:       []string{"confident"},
	}
	lowConf := rules.Finding{
		RuleID:     "GTSS-INJ-002",
		LineNumber: 10,
		CWEID:      "CWE-89",
		Severity:   rules.High,
		Confidence: "low",
		Tags:       []string{"tentative"},
	}
	got := DeduplicateFindings([]rules.Finding{lowConf, highConf})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-INJ-001" {
		t.Errorf("expected higher-confidence winner GTSS-INJ-001, got %s", got[0].RuleID)
	}
	if !hasTag(got[0].Tags, "tentative") {
		t.Error("expected merged tag 'tentative' from suppressed finding")
	}
}

func TestDedup_OrderPreservation(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(30, "CWE-79", rules.Medium, "medium"),  // group A
		taintFinding(10, "CWE-89", rules.High, "high"),       // group B (winner)
		regexFinding(10, "CWE-89", rules.Medium, "low"),      // group B (suppressed)
		astFinding(30, "CWE-79", rules.High, "high"),          // group A (winner)
	}
	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	// Group A appeared first (line 30), group B second (line 10).
	if got[0].CWEID != "CWE-79" || got[0].LineNumber != 30 {
		t.Errorf("first result should be line 30 CWE-79, got line %d %s", got[0].LineNumber, got[0].CWEID)
	}
	if got[1].CWEID != "CWE-89" || got[1].LineNumber != 10 {
		t.Errorf("second result should be line 10 CWE-89, got line %d %s", got[1].LineNumber, got[1].CWEID)
	}
}

func TestDedup_InterprocRanking(t *testing.T) {
	// Interprocedural (tier 20) beats regex (tier 10) but loses to AST (tier 30).
	findings := []rules.Finding{
		regexFinding(10, "CWE-89", rules.High, "high"),
		interprocFinding(10, "CWE-89", rules.High, "high"),
		astFinding(10, "CWE-89", rules.High, "high"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "GTSS-AST-002" {
		t.Errorf("expected AST winner over interproc and regex, got %s", got[0].RuleID)
	}
	// Interprocedural and regex tags should be merged.
	if !hasTag(got[0].Tags, "interprocedural") {
		t.Error("expected merged 'interprocedural' tag")
	}
}

func TestDedup_AllASTLanguagePrefixes(t *testing.T) {
	// Verify that isASTRuleID correctly identifies every AST analyzer prefix.
	prefixes := []struct {
		ruleID string
		lang   string
	}{
		{"GTSS-AST-001", "Go"},
		{"GTSS-PYAST-001", "Python"},
		{"GTSS-JSAST-001", "JavaScript"},
		{"GTSS-JAVAAST-001", "Java"},
		{"GTSS-PHPAST-001", "PHP"},
		{"GTSS-RUBYAST-001", "Ruby"},
		{"GTSS-CAST-001", "C"},
		{"GTSS-CS-AST-001", "C#"},
		{"GTSS-KT-AST-001", "Kotlin"},
		{"GTSS-SWIFT-AST-001", "Swift"},
		{"GTSS-RUST-AST-001", "Rust"},
		{"GTSS-LUA-AST-001", "Lua"},
		{"GTSS-GVY-AST-001", "Groovy"},
	}
	for _, p := range prefixes {
		f := rules.Finding{
			RuleID:     p.ruleID,
			LineNumber: 1,
			CWEID:      "CWE-89",
			Severity:   rules.High,
			Confidence: "high",
			Tags:       []string{"ast"},
		}
		tier := findingTier(&f)
		if tier != tierAST {
			t.Errorf("%s (%s): expected tier %d (AST), got %d", p.ruleID, p.lang, tierAST, tier)
		}
	}

	// Non-AST rule IDs must NOT be classified as AST.
	nonAST := []string{"GTSS-INJ-001", "GTSS-XSS-002", "GTSS-TAINT-sqli", "GTSS-INTERPROC-SQLI"}
	for _, id := range nonAST {
		f := rules.Finding{RuleID: id}
		if isASTRuleID(f.RuleID) && !hasTag(f.Tags, "taint-analysis") && !hasTag(f.Tags, "interprocedural") {
			// TAINT and INTERPROC are caught by tag checks before isASTRuleID,
			// so only pure regex IDs could be false positives here.
			if id == "GTSS-INJ-001" || id == "GTSS-XSS-002" {
				t.Errorf("%s: should NOT be classified as AST rule", id)
			}
		}
	}
}

func TestDedup_EmptyAndSingleInput(t *testing.T) {
	// Empty slice returns empty.
	got := DeduplicateFindings(nil)
	if len(got) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(got))
	}

	// Single finding is returned as-is.
	single := []rules.Finding{regexFinding(1, "CWE-89", rules.High, "high")}
	got = DeduplicateFindings(single)
	if len(got) != 1 {
		t.Errorf("expected 1 finding for single input, got %d", len(got))
	}
}
