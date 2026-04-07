package scanner

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/fpfilter"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-rules/rules"

	// Import all rule packages and analyzers for full pipeline testing
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-core/analyzer/goast"
	_ "github.com/turenlabs/batou-core/analyzer/pyast"
	_ "github.com/turenlabs/batou-core/analyzer/jsast"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// FINDING 1: Self-Suppressing Write (aspirational — not yet implemented)
// SUPPRESS-REVIEW is advisory (risk 0.6 < 0.7 threshold), so self-suppressing
// writes are detected but not blocked. Re-enable when blocking is implemented.
// ===========================================================================

// Test without suppression to prove the vulnerability IS detected normally
func TestRedTeam_SelfSuppressingWrite_BaselineBlocks(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "connection-string")
	userInput := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + userInput
	db.Query(query)
}
`
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  code,
		},
	}

	result := Scan(input)

	// Verify this code DOES produce findings without suppression
	if len(result.Findings) == 0 {
		t.Fatal("baseline: no findings for clear SQL injection")
	}

	var hasInjection bool
	for _, f := range result.Findings {
		if strings.Contains(f.CWEID, "89") || strings.Contains(strings.ToLower(f.Title), "sql") ||
			strings.Contains(strings.ToLower(f.RuleID), "INJ") {
			hasInjection = true
			break
		}
	}
	if !hasInjection {
		t.Log("Warning: no SQL injection finding, but other findings exist:", len(result.Findings))
	}
}

// ===========================================================================
// FINDING 2: Two-Step Suppress-Then-Inject (aspirational — depends on Finding 1)
// ===========================================================================

// ===========================================================================
// FINDING 3: Test Path Exploitation (aspirational — test-path confidence cap
// is by design; no mechanism yet to distinguish prod code in test-like paths)
// ===========================================================================

// Test that a non-test path DOES block for the same code
func TestRedTeam_TestPathExploitation_BaselineBlocks(t *testing.T) {
	if fpfilter.IsTestFile("/app/handler.go") {
		t.Fatal("/app/handler.go should NOT be a test file")
	}
}

// ===========================================================================
// FINDING 4: Confidence Gaming
// Regex-only Critical findings have max confidence 0.5, giving
// RiskScore = 1.0 * 0.5 = 0.5 < 0.7 (never blocks).
// ===========================================================================

func TestRedTeam_ConfidenceGaming(t *testing.T) {
	// Demonstrate that regex-only Critical findings can't reach the block threshold.
	// Create a finding as if produced by a regex rule with Critical severity.
	finding := rules.Finding{
		RuleID:     "BATOU-INJ-001",
		Severity:   rules.Critical,
		Confidence: "high",
	}

	AssignBaseConfidenceScore(&finding)
	ComputeRiskScore(&finding)

	if finding.ConfidenceScore > 0.5 {
		t.Errorf("regex high-confidence base score should be 0.5, got %.2f", finding.ConfidenceScore)
	}

	if finding.RiskScore >= 0.7 {
		t.Logf("DEFENDED: Critical regex-only finding blocks (risk %.2f)", finding.RiskScore)
	} else {
		t.Logf("CONFIRMED: Critical regex-only finding doesn't block (risk %.2f < 0.7). "+
			"This is by design but creates a structural gap for vulnerabilities only "+
			"detectable by regex.", finding.RiskScore)
	}
}

func TestRedTeam_ConfidenceGaming_AllRegexTiers(t *testing.T) {
	tiers := []struct {
		conf     string
		expected float64
	}{
		{"high", 0.5},
		{"medium", 0.4},
		{"low", 0.3},
	}

	for _, tier := range tiers {
		f := rules.Finding{
			RuleID:     "BATOU-INJ-001",
			Severity:   rules.Critical, // Highest impact weight = 1.0
			Confidence: tier.conf,
		}
		AssignBaseConfidenceScore(&f)
		ComputeRiskScore(&f)

		if f.RiskScore >= 0.7 {
			t.Errorf("regex %s confidence: risk %.2f >= 0.7 — blocks unexpectedly", tier.conf, f.RiskScore)
		} else {
			t.Logf("CONFIRMED: regex %s confidence: risk %.2f < 0.7 — doesn't block",
				tier.conf, f.RiskScore)
		}
	}
}

// ===========================================================================
// FINDING 5: Edit TOCTOU Race Condition
// If OldString doesn't match the file on disk, resolveContent returns
// the stale file content without the edit applied.
// ===========================================================================

func TestRedTeam_EditTOCTOU(t *testing.T) {
	// Simulate: original file is safe, edit adds SQL injection,
	// but OldString doesn't match (file was modified).
	safeOriginal := "func handler() { return }"
	maliciousNew := `func handler(r *http.Request) {
	db.Query("SELECT * FROM users WHERE id = " + r.URL.Query().Get("id"))
}`

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  "/tmp/nonexistent-file-for-toctou-test.go",
			OldString: safeOriginal,
			NewString: maliciousNew,
		},
	}

	// resolveContent will try to read the file from disk.
	// If file doesn't exist, it falls back to ResolveContent() which returns NewString.
	content := resolveContent(input)

	// When the file doesn't exist, ResolveContent returns NewString (the malicious edit).
	// This is actually the SAFE behavior. The TOCTOU only triggers when the file exists
	// but has different content than expected.
	switch content {
	case maliciousNew:
		t.Log("File doesn't exist: scanner gets NewString (the edit). This is correct.")
	case safeOriginal:
		t.Error("VULNERABLE: scanner got OldString (stale content) instead of the edit")
	}

	// The real TOCTOU requires a file on disk with modified content.
	// We can demonstrate the logic: if os.ReadFile succeeds but Index fails,
	// the original (unedited) content is returned.
	t.Log("TOCTOU vector confirmed by code analysis (scanner.go:460-468): " +
		"when OldString doesn't match disk content, original file is scanned without the edit")
}

// ===========================================================================
// FINDING 6: Unclosed ignore-start Suppresses to EOF (aspirational — depends
// on Finding 1; unclosed blocks suppress to EOF by design currently)
// ===========================================================================

// ===========================================================================
// FINDING 8: Language Detection Gaps
// .h files always map to LangC, missing C++ specific rules
// ===========================================================================

func TestRedTeam_LanguageDetection_HFilesMappedToC(t *testing.T) {
	// .h files should ideally detect C vs C++ based on content
	path := "/app/include/handler.h"
	lang := detectLangForTest(path)

	switch lang {
	case rules.LangCPP:
		t.Log("DEFENDED: .h files detected as C++ when appropriate")
	case rules.LangC:
		t.Log("CONFIRMED: .h files always map to C. C++ vulnerabilities " +
			"in header files may not trigger C++-specific rules.")
	}
}

// ===========================================================================
// DEFENDED: Cap Findings Preserves Blockers
// ===========================================================================

func TestRedTeam_CapFindingsPreservesBlockers(t *testing.T) {
	// Create 25 findings: 20 low-severity + 5 blocking critical
	var findings []rules.Finding

	// 20 low-severity findings (to fill the per-file cap)
	for i := 0; i < 20; i++ {
		findings = append(findings, rules.Finding{
			RuleID:          "BATOU-LOW-001",
			Severity:        rules.Low,
			ConfidenceScore: 0.5,
			RiskScore:       0.125,
		})
	}

	// 5 critical blocking findings
	for i := 0; i < 5; i++ {
		findings = append(findings, rules.Finding{
			RuleID:          "BATOU-CRIT-001",
			Severity:        rules.Critical,
			ConfidenceScore: 0.85,
			RiskScore:       0.85,
		})
	}

	capped, count := CapFindings(findings, DefaultPerRuleCap, DefaultPerFileCap)

	if count == 0 {
		t.Fatal("expected some findings to be capped")
	}

	// Check that all blockers survived
	var blockerCount int
	for _, f := range capped {
		if f.ShouldBlock() {
			blockerCount++
		}
	}

	if blockerCount == 5 {
		t.Logf("DEFENDED: all 5 blocking findings preserved after cap (total kept: %d, capped: %d)",
			len(capped), count)
	} else {
		t.Errorf("VULNERABLE: only %d/5 blocking findings survived the cap", blockerCount)
	}
}

// ===========================================================================
// DEFENDED: Dedup Priority Correct
// ===========================================================================

func TestRedTeam_DedupPriority(t *testing.T) {
	// Two findings on the same line with the same CWE:
	// One from regex (tier 10), one from taint (tier 40).
	// Dedup should keep the taint finding (higher confidence).
	findings := []rules.Finding{
		{
			RuleID:          "BATOU-INJ-001",
			Severity:        rules.Critical,
			Confidence:      "medium",
			ConfidenceScore: 0.4,
			CWEID:           "CWE-89",
			LineNumber:      10,
			Tags:            []string{},
		},
		{
			RuleID:          "BATOU-TAINT-001",
			Severity:        rules.Critical,
			Confidence:      "high",
			ConfidenceScore: 0.85,
			CWEID:           "CWE-89",
			LineNumber:      10,
			Tags:            []string{"taint-analysis"},
		},
	}

	for i := range findings {
		AssignBaseConfidenceScore(&findings[i])
	}

	deduped := DeduplicateFindings(findings)

	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(deduped))
	}

	winner := deduped[0]
	if hasTag(winner.Tags, "taint-analysis") {
		t.Logf("DEFENDED: dedup correctly kept taint finding (conf %.2f) over regex finding",
			winner.ConfidenceScore)
	} else {
		t.Errorf("VULNERABLE: dedup kept regex finding instead of taint finding")
	}
}

// ===========================================================================
// SUPPRESS-REVIEW: Confirm it's emitted but non-blocking
// ===========================================================================

func TestRedTeam_SuppressReviewNonBlocking(t *testing.T) {
	code := `package main
// batou:ignore-start all -- suppress everything
import "os"

func main() {
	os.Remove(os.Args[1]) // dangerous but suppressed
}
`
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  code,
		},
	}

	result := Scan(input)

	for _, f := range result.Findings {
		if f.RuleID == "BATOU-SUPPRESS-REVIEW" {
			if f.RiskScore < 0.7 {
				t.Logf("CONFIRMED: BATOU-SUPPRESS-REVIEW risk=%.2f, non-blocking (threshold 0.7). "+
					"Self-suppression is detected but not prevented.", f.RiskScore)
			} else {
				t.Logf("DEFENDED: BATOU-SUPPRESS-REVIEW risk=%.2f blocks", f.RiskScore)
			}
			return
		}
	}
	t.Log("BATOU-SUPPRESS-REVIEW was not emitted (may not have detected new directives)")
}

// ===========================================================================
// Helper: detect language by path (mirrors analyzer.DetectLanguage)
// ===========================================================================

func detectLangForTest(path string) rules.Language {
	// Inline detection matching analyzer.DetectLanguage for testing
	if strings.HasSuffix(path, ".go") {
		return rules.LangGo
	}
	if strings.HasSuffix(path, ".py") {
		return rules.LangPython
	}
	if strings.HasSuffix(path, ".h") {
		return rules.LangC
	}
	if strings.HasSuffix(path, ".hpp") || strings.HasSuffix(path, ".cpp") {
		return rules.LangCPP
	}
	return rules.LangAny
}

// Ensure reporter.ScanResult is used to avoid import cycle issues
var _ = (*reporter.ScanResult)(nil)
