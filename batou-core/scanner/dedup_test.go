package scanner

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
)

// helpers to build findings concisely in tests.

func regexFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "BATOU-INJ-001",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       tags,
	}
}

func astFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "BATOU-AST-002",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       append([]string{"ast"}, tags...),
	}
}

func taintFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "BATOU-TAINT-sqli",
		LineNumber: line,
		CWEID:      cwe,
		Severity:   sev,
		Confidence: conf,
		Tags:       append([]string{"taint-analysis", "dataflow"}, tags...),
	}
}

func interprocFinding(line int, cwe string, sev rules.Severity, conf string, tags ...string) rules.Finding {
	return rules.Finding{
		RuleID:     "BATOU-INTERPROC-SQLI",
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
	if got[0].RuleID != "BATOU-TAINT-sqli" {
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
	if got[0].RuleID != "BATOU-TAINT-sqli" {
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
	if got[0].RuleID != "BATOU-AST-002" {
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
	if got[0].RuleID != "BATOU-TAINT-sqli" {
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
		RuleID:     "BATOU-INJ-001",
		LineNumber: 10,
		CWEID:      "CWE-89",
		Severity:   rules.High,
		Confidence: "medium",
		Tags:       []string{"winner"},
	}
	medium := rules.Finding{
		RuleID:     "BATOU-INJ-002",
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
	if got[0].RuleID != "BATOU-INJ-001" {
		t.Errorf("expected higher-severity winner BATOU-INJ-001, got %s", got[0].RuleID)
	}
	if !hasTag(got[0].Tags, "loser") {
		t.Error("expected merged tag 'loser' from suppressed finding")
	}
}

func TestDedup_SameTierConfidenceTiebreak(t *testing.T) {
	highConf := rules.Finding{
		RuleID:     "BATOU-INJ-001",
		LineNumber: 10,
		CWEID:      "CWE-89",
		Severity:   rules.High,
		Confidence: "high",
		Tags:       []string{"confident"},
	}
	lowConf := rules.Finding{
		RuleID:     "BATOU-INJ-002",
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
	if got[0].RuleID != "BATOU-INJ-001" {
		t.Errorf("expected higher-confidence winner BATOU-INJ-001, got %s", got[0].RuleID)
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
	if got[0].RuleID != "BATOU-AST-002" {
		t.Errorf("expected AST winner over interproc and regex, got %s", got[0].RuleID)
	}
	// Interprocedural and regex tags should be merged.
	if !hasTag(got[0].Tags, "interprocedural") {
		t.Error("expected merged 'interprocedural' tag")
	}
}

func TestDedup_AllASTLanguagePrefixes(t *testing.T) {
	// Verify that isASTRuleID correctly identifies every AST analyzer prefix.
	// One representative rule ID per analyzer package under batou-core/analyzer/.
	prefixes := []struct {
		ruleID string
		lang   string
	}{
		{"BATOU-AST-001", "Go"},
		{"BATOU-PYAST-001", "Python"},
		{"BATOU-JSAST-001", "JavaScript"},
		{"BATOU-JAVAAST-001", "Java"},
		{"BATOU-PHPAST-001", "PHP"},
		{"BATOU-RUBYAST-001", "Ruby"},
		{"BATOU-CAST-001", "C"},
		{"BATOU-CS-AST-001", "C#"},
		{"BATOU-KT-AST-001", "Kotlin"},
		{"BATOU-SWIFT-AST-001", "Swift"},
		{"BATOU-RUST-AST-001", "Rust"},
		{"BATOU-LUA-AST-001", "Lua"},
		{"BATOU-GVY-AST-001", "Groovy"},
		{"BATOU-PERL-AST-001", "Perl"},
		{"BATOU-SH-AST-001", "Shell"},
		{"BATOU-ZIG-AST-001", "Zig"},
		{"BATOU-OWNCLOUD-AST-001", "PHP/ownCloud"},
	}
	for _, p := range prefixes {
		if !isASTRuleID(p.ruleID) {
			t.Errorf("%s (%s): isASTRuleID should be true", p.ruleID, p.lang)
		}
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

	// Non-AST rule IDs must NOT be classified as AST — including regex rule
	// IDs that happen to contain "AST" as a substring (the FASTAPI family),
	// which a substring match misclassified into the AST tier.
	nonAST := []string{
		"BATOU-INJ-001",
		"BATOU-XSS-002",
		"BATOU-TAINT-sqli",
		"BATOU-INTERPROC-SQLI",
		"BATOU-FW-FASTAPI-001",
		"BATOU-FW-FASTAPI-002",
		"BATOU-FW-FASTAPI-013",
	}
	for _, id := range nonAST {
		if isASTRuleID(id) {
			t.Errorf("%s: should NOT be classified as AST rule", id)
		}
	}

	// Untagged regex findings with an AST-substring ID must land in the
	// regex tier, not the AST tier.
	f := rules.Finding{
		RuleID:     "BATOU-FW-FASTAPI-002",
		LineNumber: 1,
		CWEID:      "CWE-346",
		Severity:   rules.Critical,
		Confidence: "high",
		Tags:       []string{"framework", "fastapi", "cors"},
	}
	if tier := findingTier(&f); tier != tierRegex {
		t.Errorf("BATOU-FW-FASTAPI-002: expected tier %d (regex), got %d", tierRegex, tier)
	}
}

func TestDedup_FASTAPIRegexCriticalDoesNotBlock(t *testing.T) {
	// Regression test for the regex-never-blocks invariant: BATOU-FW-FASTAPI-002
	// escalates to Critical for CORS wildcard + credentials. When the substring
	// "AST" in "FASTAPI" misclassified it into the AST tier it received
	// ConfBaseAST (0.7) base confidence, so RiskScore = 1.0 × 0.7 = 0.7 hit the
	// block threshold for a pure regex finding. At the correct regex base
	// (high = 0.5) RiskScore is 0.5 — a hint, not a block.
	f := rules.Finding{
		RuleID:        "BATOU-FW-FASTAPI-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		LineNumber:    10,
		CWEID:         "CWE-346",
		Confidence:    "high",
		Tags:          []string{"framework", "fastapi", "cors"},
	}
	AssignBaseConfidenceScore(&f)
	if f.ConfidenceScore != ConfBaseRegexHigh {
		t.Errorf("expected regex-high base confidence %.2f, got %.2f", ConfBaseRegexHigh, f.ConfidenceScore)
	}
	ComputeRiskScore(&f)
	if f.RiskScore >= RiskBlockThreshold {
		t.Errorf("regex-only Critical finding must not reach block threshold: RiskScore %.2f >= %.2f", f.RiskScore, RiskBlockThreshold)
	}
	if f.ShouldBlock() {
		t.Error("regex-only Critical FASTAPI-002 finding must not block")
	}
}

func TestDedup_SameLineCWEDifferentFilesSurvive(t *testing.T) {
	// Interprocedural findings can carry a caller-file FilePath that differs
	// from the scanned file, so the dedup slice mixes findings from multiple
	// files. Same (line, CWE) in different files are distinct issues — both
	// must survive.
	a := regexFinding(42, "CWE-89", rules.High, "high")
	a.FilePath = "/app/handler.go"
	b := interprocFinding(42, "CWE-89", rules.High, "high")
	b.FilePath = "/app/caller.go"

	got := DeduplicateFindings([]rules.Finding{a, b})
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (same line+CWE, different files), got %d", len(got))
	}

	// Same file, same line+CWE still dedups to one.
	c := regexFinding(42, "CWE-89", rules.High, "high")
	c.FilePath = "/app/handler.go"
	d := taintFinding(42, "CWE-89", rules.High, "high")
	d.FilePath = "/app/handler.go"
	got = DeduplicateFindings([]rules.Finding{c, d})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (same file+line+CWE), got %d", len(got))
	}
	if got[0].RuleID != "BATOU-TAINT-sqli" {
		t.Errorf("expected taint winner within same file, got %s", got[0].RuleID)
	}
}

func TestDedup_RuleIDTiebreaker(t *testing.T) {
	// When tier, severity, and confidence are identical, the lower RuleID
	// wins deterministically (prevents flaky tests from goroutine ordering).
	later := rules.Finding{
		RuleID:     "BATOU-XSS-015",
		LineNumber: 7,
		CWEID:      "CWE-79",
		Severity:   rules.High,
		Confidence: "high",
		Tags:       []string{"later-rule"},
	}
	earlier := rules.Finding{
		RuleID:     "BATOU-XSS-014",
		LineNumber: 7,
		CWEID:      "CWE-79",
		Severity:   rules.High,
		Confidence: "high",
		Tags:       []string{"earlier-rule"},
	}
	// Regardless of input order, the earlier RuleID should win.
	got := DeduplicateFindings([]rules.Finding{later, earlier})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "BATOU-XSS-014" {
		t.Errorf("expected lower RuleID winner BATOU-XSS-014, got %s", got[0].RuleID)
	}
	if !hasTag(got[0].Tags, "later-rule") {
		t.Error("expected merged tag 'later-rule' from suppressed finding")
	}

	// Reverse input order — same winner.
	got2 := DeduplicateFindings([]rules.Finding{earlier, later})
	if len(got2) != 1 {
		t.Fatalf("expected 1 finding (reversed), got %d", len(got2))
	}
	if got2[0].RuleID != "BATOU-XSS-014" {
		t.Errorf("expected lower RuleID winner (reversed) BATOU-XSS-014, got %s", got2[0].RuleID)
	}
}

func TestDedup_MultiLayerBoost(t *testing.T) {
	// Regex + taint on the same line/CWE — winner should get a boost.
	regex := regexFinding(10, "CWE-89", rules.High, "high")
	regex.ConfidenceScore = 0.5
	tf := taintFinding(10, "CWE-89", rules.High, "high")
	tf.ConfidenceScore = 0.85

	got := DeduplicateFindings([]rules.Finding{regex, tf})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	// Winner is taint (0.85) + 0.1 boost (2 distinct tiers) = 0.95
	if got[0].ConfidenceScore != 0.95 {
		t.Errorf("expected boosted score 0.95, got %.2f", got[0].ConfidenceScore)
	}
}

func TestDedup_ThreeLayerBoost(t *testing.T) {
	regex := regexFinding(10, "CWE-89", rules.High, "medium")
	regex.ConfidenceScore = 0.4
	ast := astFinding(10, "CWE-89", rules.High, "high")
	ast.ConfidenceScore = 0.7
	tf := taintFinding(10, "CWE-89", rules.High, "high")
	tf.ConfidenceScore = 0.85

	got := DeduplicateFindings([]rules.Finding{regex, ast, tf})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	// Winner is taint (0.85) + 0.2 boost (3 tiers) = 1.0 (capped)
	if got[0].ConfidenceScore != 1.0 {
		t.Errorf("expected capped score 1.0, got %.2f", got[0].ConfidenceScore)
	}
}

func TestDedup_NoCWE_NoBoost(t *testing.T) {
	// Findings without CWE are never grouped, so no boost.
	regex := regexFinding(10, "", rules.High, "high")
	regex.ConfidenceScore = 0.5
	tf := taintFinding(10, "", rules.High, "high")
	tf.ConfidenceScore = 0.85

	got := DeduplicateFindings([]rules.Finding{regex, tf})
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (no CWE), got %d", len(got))
	}
	// Scores should be unchanged.
	if got[0].ConfidenceScore != 0.5 {
		t.Errorf("regex score should be unchanged: got %.2f", got[0].ConfidenceScore)
	}
	if got[1].ConfidenceScore != 0.85 {
		t.Errorf("taint score should be unchanged: got %.2f", got[1].ConfidenceScore)
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
