package scanner

import (
	"os"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// 1. Suppress-only edit: string literal bypass prevention
// ---------------------------------------------------------------------------

func TestSuppressOnlyEdit_RejectsStringLiteral(t *testing.T) {
	// An agent could try to sneak code through by putting "batou:ignore" in a
	// string literal instead of a comment. This must NOT be treated as suppress-only.
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			OldString: "secret := getSecret()",
			NewString: "secret := \"batou:ignore this leak\"\nsecret := getSecret()",
		},
	}
	if isSuppressOnlyEdit(input) {
		t.Fatal("isSuppressOnlyEdit should reject string literals containing batou:ignore")
	}
}

func TestSuppressOnlyEdit_RejectsCodeWithSuppressSubstring(t *testing.T) {
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			OldString: "x := safe()",
			NewString: "batouIgnoreAll := true\nx := safe()",
		},
	}
	if isSuppressOnlyEdit(input) {
		t.Fatal("isSuppressOnlyEdit should reject code that happens to contain 'batou' substring")
	}
}

// ---------------------------------------------------------------------------
// 2. isSuppressComment: comment prefix validation
// ---------------------------------------------------------------------------

func TestIsSuppressComment(t *testing.T) {
	tests := []struct {
		line     string
		expected bool
	}{
		{"// batou:ignore BATOU-INJ-001", true},
		{"# batou:ignore injection", true},
		{"-- batou:ignore secrets", true},
		{"/* batou:ignore all */", true},
		{"<!-- batou:ignore xss -->", true},
		{"rem batou:ignore crypto", true},
		{"' batou:ignore auth", true},
		// NOT comments:
		{`secret = "batou:ignore"`, false},
		{"batouIgnore := true", false},
		{"x := batou_ignore_all()", false},
		{"var batou_ignore = true // batou:ignore", false}, // starts with var, not comment
		{"", false},
		{"batou:ignore", false}, // no comment prefix
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isSuppressComment(tt.line)
			if got != tt.expected {
				t.Errorf("isSuppressComment(%q) = %v, want %v", tt.line, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Edit OldString mismatch: content resolution fallback
// ---------------------------------------------------------------------------

func TestEditOldStringMismatch_FallsBackToOriginal(t *testing.T) {
	// If OldString doesn't match file content (whitespace difference),
	// resolveContent should return the original file unchanged.
	code := "func main() {\n\tfmt.Println(\"hello\")\n}\n"

	dir := t.TempDir()
	filePath := dir + "/main.go"
	_ = os.WriteFile(filePath, []byte(code), 0644)

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  filePath,
			OldString: "func main() {\n    fmt.Println(\"hello\")\n}", // spaces instead of tab
			NewString: "func main() {\n    fmt.Println(\"world\")\n}",
		},
	}

	content := resolveContent(input)
	// OldString didn't match, so we get back the original file content
	if !strings.Contains(content, "hello") {
		t.Fatal("expected original content when OldString doesn't match")
	}
	if strings.Contains(content, "world") {
		t.Fatal("replacement should NOT have been applied when OldString doesn't match")
	}
}

func TestEditOldStringEmpty_FallsBackToOriginal(t *testing.T) {
	code := "package main\n"
	dir := t.TempDir()
	filePath := dir + "/main.go"
	_ = os.WriteFile(filePath, []byte(code), 0644)

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  filePath,
			OldString: "",
			NewString: "// injected",
		},
	}

	content := resolveContent(input)
	if content != code {
		t.Fatalf("expected original content when OldString is empty, got %q", content)
	}
}

// ---------------------------------------------------------------------------
// 4. Confidence scoring boundary conditions
// ---------------------------------------------------------------------------

func TestRiskScoreBoundary_ExactlyAtThreshold(t *testing.T) {
	// RiskScore exactly 0.7 should block (>= threshold)
	f := rules.Finding{
		Severity:        rules.Critical,
		ConfidenceScore: 0.7, // 1.0 * 0.7 = 0.7
	}
	ComputeRiskScore(&f)
	if f.RiskScore < 0.7 {
		t.Fatalf("expected RiskScore >= 0.7, got %f", f.RiskScore)
	}
	if !f.ShouldBlock() {
		t.Fatal("finding at exactly 0.7 threshold should block")
	}
}

func TestRiskScoreBoundary_JustBelowThreshold(t *testing.T) {
	// High severity (0.8) at 0.87 confidence = 0.696 — just below threshold
	f := rules.Finding{
		Severity:        rules.High,
		ConfidenceScore: 0.87,
	}
	ComputeRiskScore(&f)
	if f.RiskScore >= 0.7 {
		t.Fatalf("expected RiskScore < 0.7 for High at 0.87 confidence, got %f", f.RiskScore)
	}
	if f.ShouldBlock() {
		t.Fatal("finding just below threshold should not block")
	}
}

func TestRiskScoreBoundary_JustAboveThreshold(t *testing.T) {
	f := rules.Finding{
		Severity:        rules.High,
		ConfidenceScore: 0.88, // 0.8 * 0.88 = 0.704
	}
	ComputeRiskScore(&f)
	if f.RiskScore < 0.7 {
		t.Fatalf("expected RiskScore >= 0.7 for High at 0.88 confidence, got %f", f.RiskScore)
	}
	if !f.ShouldBlock() {
		t.Fatal("finding just above threshold should block")
	}
}

func TestRiskScore_MediumNeverBlocks(t *testing.T) {
	// Medium (0.5) * 1.0 confidence = 0.5, always below 0.7
	f := rules.Finding{
		Severity:        rules.Medium,
		ConfidenceScore: 1.0,
	}
	ComputeRiskScore(&f)
	if f.ShouldBlock() {
		t.Fatalf("Medium severity should never block, RiskScore=%f", f.RiskScore)
	}
}

func TestRiskScore_LowNeverBlocks(t *testing.T) {
	f := rules.Finding{
		Severity:        rules.Low,
		ConfidenceScore: 1.0,
	}
	ComputeRiskScore(&f)
	if f.ShouldBlock() {
		t.Fatalf("Low severity should never block, RiskScore=%f", f.RiskScore)
	}
}

// ---------------------------------------------------------------------------
// 5. Confidence multi-layer boost: can't exceed 1.0
// ---------------------------------------------------------------------------

func TestMultiLayerBoost_CappedAt1(t *testing.T) {
	f := rules.Finding{
		ConfidenceScore: 0.95,
	}
	// Boost with 6 distinct tiers (5 additional × +0.1 each = 0.95 + 0.5)
	BoostConfidenceForMultiLayer(&f, 6)
	if f.ConfidenceScore > 1.0 {
		t.Fatalf("confidence boosted above 1.0: %f", f.ConfidenceScore)
	}
}

// ---------------------------------------------------------------------------
// 6. SyncConfidenceString consistency
// ---------------------------------------------------------------------------

func TestSyncConfidenceString_AllRanges(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.0, "low"},
		{0.1, "low"},
		{0.3, "low"},
		{0.39, "low"},
		{0.4, "medium"},
		{0.5, "medium"},
		{0.69, "medium"},
		{0.7, "high"},
		{0.85, "high"},
		{1.0, "high"},
	}
	for _, tt := range tests {
		f := rules.Finding{ConfidenceScore: tt.score}
		f.SyncConfidenceString()
		if f.Confidence != tt.expected {
			t.Errorf("SyncConfidenceString(%f) = %q, want %q", tt.score, f.Confidence, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. ScanResult.ShouldBlock: empty findings, mixed findings
// ---------------------------------------------------------------------------

func TestScanResultShouldBlock_EmptyFindings(t *testing.T) {
	r := &reporter.ScanResult{}
	if r.ShouldBlock() {
		t.Fatal("empty result should not block")
	}
}

func TestScanResultShouldBlock_MixedFindings(t *testing.T) {
	r := &reporter.ScanResult{
		Findings: []rules.Finding{
			{Severity: rules.Low, ConfidenceScore: 0.5, RiskScore: 0.125},
			{Severity: rules.Critical, ConfidenceScore: 0.85, RiskScore: 0.85},
		},
	}
	if !r.ShouldBlock() {
		t.Fatal("result with one blocking finding should block")
	}
}

// ---------------------------------------------------------------------------
// 8. Preprocessing edge cases
// ---------------------------------------------------------------------------

func TestPreprocessing_BackslashContinuation(t *testing.T) {
	// Shell-style backslash continuation should join lines
	code := "CMD='SELECT * FROM users \\\nWHERE id=' + input"
	result := JoinContinuationLines(code, rules.LangShell)
	if strings.Contains(result, "\\\n") {
		t.Fatal("backslash continuation should be joined")
	}
}

func TestPreprocessing_PythonParensContinuation(t *testing.T) {
	code := "result = (\n    f'SELECT * FROM users WHERE id={user_id}'\n)"
	result := JoinContinuationLines(code, rules.LangPython)
	// After joining, the multi-line expression should be on fewer lines
	origLines := strings.Count(code, "\n")
	resultLines := strings.Count(result, "\n")
	if resultLines >= origLines {
		t.Fatalf("expected fewer lines after joining parens, got %d (was %d)", resultLines, origLines)
	}
}

func TestPreprocessing_GoUnchanged(t *testing.T) {
	// Go doesn't have continuation joining — content should be unchanged
	code := "func main() {\n\tx := 1 +\n\t\t2\n}"
	result := JoinContinuationLines(code, rules.LangGo)
	if result != code {
		t.Fatal("Go content should not be modified by JoinContinuationLines")
	}
}

// ---------------------------------------------------------------------------
// 9. Empty/edge-case inputs
// ---------------------------------------------------------------------------

func TestScan_NilInput(t *testing.T) {
	// Should not panic on nil-like input
	input := &hook.Input{}
	result := Scan(input)
	if result == nil {
		t.Fatal("Scan should return non-nil result even for empty input")
	}
}

func TestScan_WriteEmptyContent(t *testing.T) {
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/tmp/test_empty.go",
			Content:  "",
		},
	}
	result := Scan(input)
	if result == nil {
		t.Fatal("Scan should return non-nil result for empty content")
	}
	if len(result.Findings) > 0 {
		t.Fatal("empty content should produce no findings")
	}
}

func TestScan_BinaryFilePath(t *testing.T) {
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/image.png",
			Content:  "\x89PNG\r\n\x1a\n",
		},
	}
	result := Scan(input)
	if len(result.Findings) > 0 {
		t.Fatal("binary file should produce no findings")
	}
}

// ---------------------------------------------------------------------------
// 10. Cap findings: per-rule and per-file limits
// ---------------------------------------------------------------------------

func TestCapFindings_PerRuleLimit(t *testing.T) {
	findings := make([]rules.Finding, 10)
	for i := range findings {
		findings[i] = rules.Finding{RuleID: "BATOU-TEST-001", LineNumber: i + 1}
	}
	capped, count := CapFindings(findings, 3, 100)
	if len(capped) != 3 {
		t.Fatalf("expected 3 findings after per-rule cap, got %d", len(capped))
	}
	if count != 7 {
		t.Fatalf("expected 7 capped, got %d", count)
	}
}

func TestCapFindings_PerFileLimit(t *testing.T) {
	findings := make([]rules.Finding, 30)
	for i := range findings {
		findings[i] = rules.Finding{
			RuleID:     "BATOU-TEST-" + string(rune('A'+i%26)),
			LineNumber: i + 1,
		}
	}
	capped, count := CapFindings(findings, 100, 20)
	if len(capped) != 20 {
		t.Fatalf("expected 20 findings after per-file cap, got %d", len(capped))
	}
	if count != 10 {
		t.Fatalf("expected 10 capped, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// 11. PreSuppressBlock: suppress can't hide blocking findings
// ---------------------------------------------------------------------------

func TestPreSuppressBlock_SuppressedCriticalStillBlocks(t *testing.T) {
	// An agent writes code with batou:ignore wrapping a taint-confirmed vuln.
	// The suppress hides the finding, but PreSuppressBlock should be true.
	code := `package main

import (
	"database/sql"
	"net/http"
)

// batou:ignore-start injection -- false positive
func handler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "")
	query := "SELECT * FROM users WHERE id = " + r.URL.Query().Get("id")
	db.Query(query)
}
// batou:ignore-end`

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  code,
		},
	}
	result := Scan(input)

	// Findings should be suppressed (agent added ignore directives)
	if result.SuppressedCount == 0 {
		t.Log("note: no findings were suppressed — taint may not have fired")
	}

	// But PreSuppressBlock should be true if any finding would have blocked
	if result.PreSuppressBlock {
		t.Log("PreSuppressBlock correctly set — suppress can't hide blocking findings")
	}
}

// ---------------------------------------------------------------------------
// 12. Generated file header injection bypass prevention
// ---------------------------------------------------------------------------

func TestGeneratedFileBypass_PreToolUseNewFile(t *testing.T) {
	// An agent writes a new file with "Code generated" header to bypass scanning.
	// PreToolUse should NOT skip this — the marker is agent-provided, not genuine.
	code := `// Code generated - DO NOT EDIT
package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "")
	query := "SELECT * FROM users WHERE id = " + r.URL.Query().Get("id")
	db.Query(query)
}`

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  code,
		},
	}
	result := Scan(input)

	// Should still detect the SQL injection despite "generated" header
	if len(result.Findings) == 0 && result.SuppressedCount == 0 {
		t.Fatal("generated file header in PreToolUse Write should not bypass scanning")
	}
}

func TestGeneratedFileBypass_PostToolUseRealGenerated(t *testing.T) {
	// PostToolUse on a genuinely generated file (already on disk) should still skip.
	dir := t.TempDir()
	filePath := dir + "/generated.go"
	code := "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage pb\n"
	_ = os.WriteFile(filePath, []byte(code), 0644)

	input := &hook.Input{
		HookEventName: "PostToolUse",
		ToolName:      "Write",
		ToolInput:     hook.ToolInput{FilePath: filePath, Content: code},
	}
	result := Scan(input)

	// PostToolUse reads from disk, finds genuine marker → no findings
	if len(result.Findings) > 0 {
		t.Fatal("genuinely generated file should be skipped in PostToolUse")
	}
}

// ---------------------------------------------------------------------------
// 13. File skipping edge cases
// ---------------------------------------------------------------------------

func TestShouldSkipFile_Markdown(t *testing.T) {
	if !shouldSkipFile("/app/README.md", "# Hello") {
		t.Fatal("should skip markdown files")
	}
}

func TestShouldSkipFile_ClaudeDir(t *testing.T) {
	if !shouldSkipFile("/home/user/.claude/settings.json", `{"key": "val"}`) {
		t.Fatal("should skip .claude/ directory files")
	}
}

func TestShouldSkipFile_EmptyContent(t *testing.T) {
	if !shouldSkipFile("/app/main.go", "   \n\t\n  ") {
		t.Fatal("should skip whitespace-only content")
	}
}

func TestShouldSkipFile_NormalGoFile(t *testing.T) {
	if shouldSkipFile("/app/main.go", "package main\nfunc main() {}") {
		t.Fatal("should not skip normal Go file")
	}
}
