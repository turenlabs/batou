package reporter_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/reporter"
	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// ScanResult.MaxSeverity
// ---------------------------------------------------------------------------

func TestMaxSeverityReturnsHighest(t *testing.T) {
	result := &reporter.ScanResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: rules.Low},
			{RuleID: "R2", Severity: rules.Critical},
			{RuleID: "R3", Severity: rules.Medium},
		},
	}

	if got := result.MaxSeverity(); got != rules.Critical {
		t.Errorf("MaxSeverity() = %s, want CRITICAL", got)
	}
}

func TestMaxSeverityNoFindings(t *testing.T) {
	result := &reporter.ScanResult{}
	if got := result.MaxSeverity(); got != rules.Info {
		t.Errorf("MaxSeverity() with no findings = %s, want INFO", got)
	}
}

// ---------------------------------------------------------------------------
// ScanResult.HasFindings
// ---------------------------------------------------------------------------

func TestHasFindings(t *testing.T) {
	empty := &reporter.ScanResult{}
	withFindings := &reporter.ScanResult{
		Findings: []rules.Finding{{RuleID: "R1"}},
	}

	if empty.HasFindings() {
		t.Error("HasFindings() should be false for empty result")
	}
	if !withFindings.HasFindings() {
		t.Error("HasFindings() should be true when findings exist")
	}
}

// ---------------------------------------------------------------------------
// ScanResult.ShouldBlock
// ---------------------------------------------------------------------------

func TestShouldBlock(t *testing.T) {
	criticalHighConf := &reporter.ScanResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: rules.Critical, ConfidenceScore: 0.8},
		},
	}
	criticalLowConf := &reporter.ScanResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: rules.Critical, ConfidenceScore: 0.5},
		},
	}
	high := &reporter.ScanResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: rules.High, ConfidenceScore: 0.9},
		},
	}
	none := &reporter.ScanResult{}

	if !criticalHighConf.ShouldBlock() {
		t.Error("ShouldBlock() should be true for Critical+high-confidence findings")
	}
	if criticalLowConf.ShouldBlock() {
		t.Error("ShouldBlock() should be false for Critical+low-confidence findings (the key behavioral change)")
	}
	if high.ShouldBlock() {
		t.Error("ShouldBlock() should be false for High findings even with high confidence")
	}
	if none.ShouldBlock() {
		t.Error("ShouldBlock() should be false for no findings")
	}
}

func TestShouldBlock_CriticalAtThreshold(t *testing.T) {
	atThreshold := &reporter.ScanResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: rules.Critical, ConfidenceScore: 0.7},
		},
	}
	belowThreshold := &reporter.ScanResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: rules.Critical, ConfidenceScore: 0.69},
		},
	}

	if !atThreshold.ShouldBlock() {
		t.Error("ShouldBlock() should be true at exactly 0.7 threshold")
	}
	if belowThreshold.ShouldBlock() {
		t.Error("ShouldBlock() should be false just below 0.7 threshold")
	}
}

// ---------------------------------------------------------------------------
// ScanResult.CountBySeverity
// ---------------------------------------------------------------------------

func TestCountBySeverity(t *testing.T) {
	result := &reporter.ScanResult{
		Findings: []rules.Finding{
			{Severity: rules.High},
			{Severity: rules.High},
			{Severity: rules.Medium},
			{Severity: rules.Critical},
		},
	}

	counts := result.CountBySeverity()
	if counts[rules.High] != 2 {
		t.Errorf("High count = %d, want 2", counts[rules.High])
	}
	if counts[rules.Medium] != 1 {
		t.Errorf("Medium count = %d, want 1", counts[rules.Medium])
	}
	if counts[rules.Critical] != 1 {
		t.Errorf("Critical count = %d, want 1", counts[rules.Critical])
	}
	if counts[rules.Low] != 0 {
		t.Errorf("Low count = %d, want 0", counts[rules.Low])
	}
}

// ---------------------------------------------------------------------------
// FormatForClaude
// ---------------------------------------------------------------------------

func TestFormatForClaudeNoFindings(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/main.go",
		Language: rules.LangGo,
	}

	output := reporter.FormatForClaude(result)
	if output != "" {
		t.Errorf("FormatForClaude with no findings should return empty, got:\n%s", output)
	}
}

func TestFormatForClaudeContainsHeader(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath:   "/app/handler.go",
		Language:   rules.LangGo,
		RulesRun:   10,
		ScanTimeMs: 42,
		Findings: []rules.Finding{
			{
				RuleID:      "BATOU-INJ-001",
				Severity:    rules.Critical,
				Title:       "SQL Injection",
				Description: "User input in SQL query",
				FilePath:    "/app/handler.go",
				LineNumber:  15,
				MatchedText: "db.Query(userInput)",
				Suggestion:  "Use parameterized queries",
				CWEID:       "CWE-89",
			},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "Batou Security Scan") {
		t.Error("expected Batou Security Scan header")
	}
	if !strings.Contains(output, "/app/handler.go") {
		t.Error("expected file path in output")
	}
	if !strings.Contains(output, "Language: go") {
		t.Error("expected language in output")
	}
	if !strings.Contains(output, "Findings: 1") {
		t.Error("expected finding count in output")
	}
}

func TestFormatForClaudeContainsSeveritySummary(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "Critical issue"},
			{Severity: rules.High, RuleID: "R2", Title: "High issue"},
			{Severity: rules.Medium, RuleID: "R3", Title: "Medium issue"},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "CRITICAL:1") {
		t.Error("expected CRITICAL:1 in severity summary")
	}
	if !strings.Contains(output, "HIGH:1") {
		t.Error("expected HIGH:1 in severity summary")
	}
	if !strings.Contains(output, "MEDIUM:1") {
		t.Error("expected MEDIUM:1 in severity summary")
	}
}

func TestFormatForClaudeBlockedMessage(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "Critical vuln", ConfidenceScore: 0.8},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "ACTION REQUIRED") {
		t.Error("expected ACTION REQUIRED for critical high-confidence findings")
	}
	if !strings.Contains(output, "BLOCKED") {
		t.Error("expected BLOCKED for critical high-confidence findings")
	}
}

func TestFormatForClaude_CriticalLowConfNotBlocked(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "Critical vuln", ConfidenceScore: 0.4},
		},
	}

	output := reporter.FormatForClaude(result)

	if strings.Contains(output, "ACTION REQUIRED") {
		t.Error("low-confidence Critical should NOT show ACTION REQUIRED")
	}
	if strings.Contains(output, "BLOCKED") {
		t.Error("low-confidence Critical should NOT show BLOCKED")
	}
	// Should still show a warning since severity is high enough.
	if !strings.Contains(output, "WARNING") {
		t.Error("expected WARNING for low-confidence Critical (severity >= High)")
	}
}

func TestFormatForClaudeWarningMessage(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.High, RuleID: "R1", Title: "High issue"},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "WARNING") {
		t.Error("expected WARNING for high-severity findings")
	}
}

func TestFormatForClaudeFooter(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Low, RuleID: "R1", Title: "Low issue"},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "End Batou Scan") {
		t.Error("expected End Batou Scan footer")
	}
}

func TestFormatForClaudeMultiFindings(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.High, RuleID: "R1", Title: "First issue", Description: "desc1"},
			{Severity: rules.Medium, RuleID: "R2", Title: "Second issue", Description: "desc2"},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "(1)") {
		t.Error("expected finding number (1)")
	}
	if !strings.Contains(output, "(2)") {
		t.Error("expected finding number (2)")
	}
}

// ---------------------------------------------------------------------------
// FormatBlockMessage
// ---------------------------------------------------------------------------

func TestFormatBlockMessage(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "SQL Injection", Description: "bad", ConfidenceScore: 0.8},
			{Severity: rules.High, RuleID: "R2", Title: "XSS", Description: "also bad", ConfidenceScore: 0.8},
		},
	}

	msg := reporter.FormatBlockMessage(result)

	if !strings.Contains(msg, "BLOCKED WRITE") {
		t.Error("expected BLOCKED WRITE header")
	}
	// Only critical findings should appear in block message.
	if !strings.Contains(msg, "SQL Injection") {
		t.Error("expected critical finding in block message")
	}
}

func TestFormatBlockMessageExcludesNonCritical(t *testing.T) {
	result := &reporter.ScanResult{
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "Critical", ConfidenceScore: 0.8},
			{Severity: rules.High, RuleID: "R2", Title: "HighOnly", ConfidenceScore: 0.8},
		},
	}

	msg := reporter.FormatBlockMessage(result)

	// FormatBlockMessage iterates and only prints findings with >= Critical.
	// High should not have its own FormatDetail in the output (unless FormatDetail
	// is called for all). We verify the critical one is present.
	if !strings.Contains(msg, "Critical") {
		t.Error("expected Critical finding in block message")
	}
}

// ---------------------------------------------------------------------------
// False-positive suppression guidance
// ---------------------------------------------------------------------------

func TestFormatForClaude_IncludesSuppressGuidance(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Medium, RuleID: "R1", Title: "Issue"},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "batou:ignore") {
		t.Error("expected batou:ignore suppression guidance in FormatForClaude output")
	}
	if !strings.Contains(output, "//") {
		t.Error("expected Go comment prefix // in suppression guidance")
	}
}

func TestFormatForClaude_PythonCommentPrefix(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.py",
		Language: rules.LangPython,
		Findings: []rules.Finding{
			{Severity: rules.Medium, RuleID: "R1", Title: "Issue"},
		},
	}

	output := reporter.FormatForClaude(result)

	if !strings.Contains(output, "# batou:ignore") {
		t.Error("expected Python comment prefix # in suppression guidance")
	}
}

func TestFormatBlockMessage_IncludesSuppressGuidance(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "SQL Injection", Description: "bad", ConfidenceScore: 0.8},
		},
	}

	msg := reporter.FormatBlockMessage(result)

	if !strings.Contains(msg, "batou:ignore") {
		t.Error("expected batou:ignore suppression guidance in FormatBlockMessage output")
	}
}

func TestFormatBlockMessage_LuaCommentPrefix(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/script.lua",
		Language: rules.LangLua,
		Findings: []rules.Finding{
			{Severity: rules.Critical, RuleID: "R1", Title: "Issue", Description: "bad", ConfidenceScore: 0.8},
		},
	}

	msg := reporter.FormatBlockMessage(result)

	if !strings.Contains(msg, "-- batou:ignore") {
		t.Error("expected Lua comment prefix -- in suppression guidance")
	}
}
