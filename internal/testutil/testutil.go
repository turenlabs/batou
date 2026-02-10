// Package testutil provides test helpers for GTSS rule and scanner testing.
//
// It wraps the scanner pipeline so tests can feed in arbitrary code strings
// and assert on findings without constructing hook.Input structs by hand.
package testutil

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/turen/gtss/internal/hook"
	"github.com/turen/gtss/internal/reporter"
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/scanner"
)

// ScanResult wraps reporter.ScanResult with convenience accessors for tests.
type ScanResult struct {
	Findings []rules.Finding
	Blocked  bool
	Raw      *reporter.ScanResult
}

// fromReporter converts a reporter.ScanResult to a testutil.ScanResult.
func fromReporter(r *reporter.ScanResult) *ScanResult {
	return &ScanResult{
		Findings: r.Findings,
		Blocked:  r.ShouldBlock(),
		Raw:      r,
	}
}

// ScanContent scans arbitrary content as if it were being written to filePath.
// The filePath determines language detection (e.g., "test.go" -> Go rules).
func ScanContent(t *testing.T, filePath string, content string) *ScanResult {
	t.Helper()

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: filePath,
			Content:  content,
		},
	}

	result := scanner.Scan(input)
	return fromReporter(result)
}

// ScanContentAsEdit scans content as if it were an edit operation, providing
// both old and new text for delta-aware rules.
func ScanContentAsEdit(t *testing.T, filePath, oldText, newText, fullContent string) *ScanResult {
	t.Helper()

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  filePath,
			OldString: oldText,
			NewString: newText,
			Content:   fullContent,
		},
	}

	result := scanner.Scan(input)
	return fromReporter(result)
}

// ScanFixture loads a fixture file from the testdata/fixtures directory and
// scans it. The fixturePath is relative to testdata/fixtures/.
func ScanFixture(t *testing.T, fixturePath string) *ScanResult {
	t.Helper()

	fullPath := FixtureDir() + "/" + fixturePath
	content := LoadFixture(t, fixturePath)
	return ScanContent(t, fullPath, content)
}

// ScanRules runs only the registered rules against content, bypassing the
// full scanner pipeline (no taint analysis, no call graph, no hints).
// Useful for targeted unit tests of individual rule categories.
func ScanRules(t *testing.T, filePath string, content string, lang rules.Language) *ScanResult {
	t.Helper()

	ctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  content,
		Language: lang,
		IsNew:    true,
	}

	applicable := rules.ForLanguage(lang)
	var findings []rules.Finding
	for _, r := range applicable {
		findings = append(findings, r.Scan(ctx)...)
	}

	blocked := false
	for _, f := range findings {
		if f.Severity >= rules.Critical {
			blocked = true
			break
		}
	}

	return &ScanResult{
		Findings: findings,
		Blocked:  blocked,
		Raw: &reporter.ScanResult{
			FilePath: filePath,
			Language: lang,
			Findings: findings,
			RulesRun: len(applicable),
		},
	}
}

// --- Assertion helpers ---

// MustFindRule asserts that at least one finding with the given ruleID exists.
func MustFindRule(t *testing.T, result *ScanResult, ruleID string) {
	t.Helper()
	if !HasFinding(result, ruleID) {
		t.Errorf("expected finding with rule ID %q but none found; got %d findings: %s",
			ruleID, len(result.Findings), summarizeFindings(result.Findings))
	}
}

// MustNotFindRule asserts that no finding with the given ruleID exists.
func MustNotFindRule(t *testing.T, result *ScanResult, ruleID string) {
	t.Helper()
	if HasFinding(result, ruleID) {
		for _, f := range result.Findings {
			if f.RuleID == ruleID {
				t.Errorf("expected no finding with rule ID %q but found: %s (line %d)",
					ruleID, f.Title, f.LineNumber)
			}
		}
	}
}

// HasFinding returns true if any finding matches the given ruleID.
func HasFinding(result *ScanResult, ruleID string) bool {
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// HasFindingWithSeverity returns true if a finding matches both ruleID and severity.
func HasFindingWithSeverity(result *ScanResult, ruleID string, sev rules.Severity) bool {
	for _, f := range result.Findings {
		if f.RuleID == ruleID && f.Severity == sev {
			return true
		}
	}
	return false
}

// CountFindings returns the total number of findings.
func CountFindings(result *ScanResult) int {
	return len(result.Findings)
}

// CountBySeverity returns the number of findings at a given severity level.
func CountBySeverity(result *ScanResult, severity rules.Severity) int {
	count := 0
	for _, f := range result.Findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}

// CountBySeverityLabel returns the number of findings matching a severity label string.
// Accepted values: "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL".
func CountBySeverityLabel(result *ScanResult, label string) int {
	sev := parseSeverityLabel(label)
	return CountBySeverity(result, sev)
}

// AssertBlocked asserts that the scan result should block the write
// (i.e., at least one Critical severity finding exists).
func AssertBlocked(t *testing.T, result *ScanResult) {
	t.Helper()
	if !result.Blocked {
		t.Errorf("expected scan to be blocked (Critical severity) but it was not; "+
			"highest severity among %d findings: %s",
			len(result.Findings), highestSeverity(result.Findings))
	}
}

// AssertNotBlocked asserts that the scan result does NOT block the write.
func AssertNotBlocked(t *testing.T, result *ScanResult) {
	t.Helper()
	if result.Blocked {
		t.Errorf("expected scan to not be blocked but it was; critical findings: %s",
			criticalFindings(result.Findings))
	}
}

// AssertAllowed is an alias for AssertNotBlocked -- asserts the scan would
// allow the write (no Critical severity findings).
func AssertAllowed(t *testing.T, result *ScanResult) {
	t.Helper()
	AssertNotBlocked(t, result)
}

// RunGTSSBinary compiles and runs the gtss binary with the given hook input
// fed as JSON via stdin. Returns the process exit code, stdout, and stderr.
// The binary is built once per test binary invocation and cached in a temp dir.
//
// hookInput is marshaled to JSON and piped to stdin, mimicking how Claude Code
// hooks invoke GTSS.
func RunGTSSBinary(t *testing.T, hookInput map[string]interface{}) (exitCode int, stdout string, stderr string) {
	t.Helper()

	binPath := buildGTSSBinary(t)

	inputJSON, err := json.Marshal(hookInput)
	if err != nil {
		t.Fatalf("failed to marshal hook input: %v", err)
	}

	cmd := exec.Command(binPath)
	cmd.Stdin = bytes.NewReader(inputJSON)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()

	exitCode = 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run gtss binary: %v", runErr)
		}
	}

	return exitCode, outBuf.String(), errBuf.String()
}

// gtssBinaryPath caches the compiled binary path for the test session.
var gtssBinaryPath string

// buildGTSSBinary compiles cmd/gtss/main.go into a temp binary, reusing it
// across calls within the same test process.
func buildGTSSBinary(t *testing.T) string {
	t.Helper()

	if gtssBinaryPath != "" {
		if _, err := os.Stat(gtssBinaryPath); err == nil {
			return gtssBinaryPath
		}
	}

	// Find the project root from this source file
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine project root via runtime.Caller")
	}
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "gtss")

	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/gtss")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build gtss binary: %v\n%s", err, output)
	}

	gtssBinaryPath = binPath
	return binPath
}

// AssertMinFindings asserts at least n findings were produced.
func AssertMinFindings(t *testing.T, result *ScanResult, n int) {
	t.Helper()
	if len(result.Findings) < n {
		t.Errorf("expected at least %d findings but got %d: %s",
			n, len(result.Findings), summarizeFindings(result.Findings))
	}
}

// AssertNoFindings asserts zero findings were produced.
func AssertNoFindings(t *testing.T, result *ScanResult) {
	t.Helper()
	if len(result.Findings) > 0 {
		t.Errorf("expected no findings but got %d: %s",
			len(result.Findings), summarizeFindings(result.Findings))
	}
}

// FindingsByRule returns all findings matching the given ruleID.
func FindingsByRule(result *ScanResult, ruleID string) []rules.Finding {
	var out []rules.Finding
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// FindingRuleIDs returns a deduplicated list of all rule IDs present in results.
func FindingRuleIDs(result *ScanResult) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, f := range result.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
		}
	}
	return ids
}

// --- internal helpers ---

func summarizeFindings(findings []rules.Finding) string {
	if len(findings) == 0 {
		return "(none)"
	}
	s := ""
	for i, f := range findings {
		if i > 0 {
			s += ", "
		}
		s += f.RuleID
		if i >= 9 {
			s += "... (truncated)"
			break
		}
	}
	return s
}

func criticalFindings(findings []rules.Finding) string {
	s := ""
	for _, f := range findings {
		if f.Severity >= rules.Critical {
			if s != "" {
				s += ", "
			}
			s += f.RuleID
		}
	}
	if s == "" {
		return "(none)"
	}
	return s
}

func highestSeverity(findings []rules.Finding) string {
	max := rules.Info
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max.String()
}

func parseSeverityLabel(label string) rules.Severity {
	switch label {
	case "CRITICAL":
		return rules.Critical
	case "HIGH":
		return rules.High
	case "MEDIUM":
		return rules.Medium
	case "LOW":
		return rules.Low
	default:
		return rules.Info
	}
}
