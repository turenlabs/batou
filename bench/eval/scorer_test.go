package eval

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/rules"
)

// testdataDir returns the absolute path to the testdata directory
// adjacent to this test file.
func testdataDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "testdata"
	}
	baseDir := filepath.Dir(thisFile)
	dir := filepath.Clean(filepath.Join(baseDir, "testdata"))
	// Ensure the resolved path stays within the source directory.
	if !strings.HasPrefix(dir, baseDir) {
		return "testdata"
	}
	return dir
}

// loadTestFixture reads a file from the testdata directory.
func loadTestFixture(t *testing.T, name string) string {
	t.Helper()
	dir := testdataDir()
	p := filepath.Clean(filepath.Join(dir, name))
	if !strings.HasPrefix(p, dir) {
		t.Fatalf("path %q escapes testdata directory", name)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to load test fixture %q: %v", name, err)
	}
	return string(data)
}

// TestScoreSample_VulnerableGoSQL verifies that a known SQL injection pattern
// in Go is detected and scored correctly.
func TestScoreSample_VulnerableGoSQL(t *testing.T) {
	prompt := Prompt{
		ID:    "sql-injection-go",
		OWASP: "A03",
		CWEs:  []string{"CWE-89"},
	}

	sample := GeneratedSample{
		PromptID: "sql-injection-go",
		Language: "go",
		Code:     loadTestFixture(t, "vuln_go_sqli.go.txt"),
	}

	result := ScoreSample(prompt, sample)

	if !result.VulnerabilityFound {
		t.Error("expected vulnerability to be detected in SQL injection sample")
	}

	if result.SeverityMax < rules.High {
		t.Errorf("expected severity >= High, got %s", result.SeverityMaxLabel)
	}

	if len(result.RuleIDs) == 0 {
		t.Error("expected at least one rule ID to fire")
	}

	if result.SeverityScore <= 0 {
		t.Errorf("expected positive severity score, got %.1f", result.SeverityScore)
	}
}

// TestScoreSample_SafeGoParameterized verifies that a parameterized query
// in Go is not flagged as vulnerable.
func TestScoreSample_SafeGoParameterized(t *testing.T) {
	prompt := Prompt{
		ID:    "sql-injection-go",
		OWASP: "A03",
		CWEs:  []string{"CWE-89"},
	}

	sample := GeneratedSample{
		PromptID: "sql-injection-go",
		Language: "go",
		Code:     loadTestFixture(t, "safe_go_sqli.go.txt"),
	}

	result := ScoreSample(prompt, sample)

	// Parameterized queries should not trigger SQL injection rules
	hasInjection := false
	for _, id := range result.RuleIDs {
		if strings.Contains(id, "INJ") {
			hasInjection = true
		}
	}
	if hasInjection {
		t.Errorf("parameterized query should not trigger injection rules, got: %v", result.RuleIDs)
	}
}

// TestScoreSample_VulnerablePythonSQLi verifies Python SQL injection detection.
func TestScoreSample_VulnerablePythonSQLi(t *testing.T) {
	prompt := Prompt{
		ID:    "sql-injection-python",
		OWASP: "A03",
		CWEs:  []string{"CWE-89"},
	}

	sample := GeneratedSample{
		PromptID: "sql-injection-python",
		Language: "python",
		Code:     loadTestFixture(t, "vuln_py_sqli.py.txt"),
	}

	result := ScoreSample(prompt, sample)

	if !result.VulnerabilityFound {
		t.Error("expected vulnerability to be detected in Python SQL injection sample")
	}

	if result.FindingCount == 0 {
		t.Error("expected at least one finding")
	}
}

// TestAggregateModel verifies aggregate metric computation.
func TestAggregateModel(t *testing.T) {
	results := []EvalResult{
		{
			PromptID:           "p1",
			Language:           "go",
			VulnerabilityFound: true,
			SeverityMax:        rules.Critical,
			SeverityMaxLabel:   "CRITICAL",
			SeverityScore:      10.0,
			CWEMatched:         true,
			OWASPMatched:       true,
			RuleIDs:            []string{"BATOU-INJ-001"},
			FindingCount:       1,
		},
		{
			PromptID:           "p2",
			Language:           "python",
			VulnerabilityFound: true,
			SeverityMax:        rules.High,
			SeverityMaxLabel:   "HIGH",
			SeverityScore:      7.0,
			CWEMatched:         true,
			OWASPMatched:       false,
			RuleIDs:            []string{"BATOU-INJ-002"},
			FindingCount:       1,
		},
		{
			PromptID:           "p3",
			Language:           "go",
			VulnerabilityFound: false,
			SeverityMax:        rules.Info,
			SeverityMaxLabel:   "INFO",
			SeverityScore:      0,
			CWEMatched:         false,
			OWASPMatched:       false,
			FindingCount:       0,
		},
	}

	report := AggregateModel("test-model", results)

	if report.TotalSamples != 3 {
		t.Errorf("expected 3 total samples, got %d", report.TotalSamples)
	}

	if report.VulnerableCount != 2 {
		t.Errorf("expected 2 vulnerable, got %d", report.VulnerableCount)
	}

	expectedVR := 2.0 / 3.0
	if floatAbs(report.VulnerabilityRate-expectedVR) > 0.01 {
		t.Errorf("expected vulnerability rate %.2f, got %.2f", expectedVR, report.VulnerabilityRate)
	}

	expectedAvgSev := 17.0 / 3.0
	if floatAbs(report.SeverityScoreAvg-expectedAvgSev) > 0.01 {
		t.Errorf("expected avg severity score %.2f, got %.2f", expectedAvgSev, report.SeverityScoreAvg)
	}

	// F1: precision=1.0 (2 detected, 0 FP), recall=2/3
	// F1 = 2 * 1.0 * 0.667 / (1.0 + 0.667) = 0.8
	if report.F1 < 0.79 || report.F1 > 0.81 {
		t.Errorf("expected F1 ~0.80, got %.2f", report.F1)
	}

	if report.PSBScore <= 0 || report.PSBScore > 100 {
		t.Errorf("PSB score should be 0-100, got %.1f", report.PSBScore)
	}

	// Check language breakdown
	goStats, ok := report.ByLanguage["go"]
	if !ok {
		t.Fatal("expected 'go' in language breakdown")
	}
	if goStats.Total != 2 {
		t.Errorf("expected 2 go samples, got %d", goStats.Total)
	}
	if goStats.Vulnerable != 1 {
		t.Errorf("expected 1 go vulnerable, got %d", goStats.Vulnerable)
	}
}

// TestFormatTable verifies that table output contains expected sections.
func TestFormatTable(t *testing.T) {
	report := ModelReport{
		Model:             "test-model",
		TotalSamples:      10,
		VulnerableCount:   8,
		VulnerabilityRate: 0.8,
		SeverityScoreAvg:  5.5,
		PSBScore:          72.5,
		Precision:         1.0,
		Recall:            0.8,
		F1:                0.89,
		BySeverity:        map[string]int{"CRITICAL": 3, "HIGH": 5},
		ByLanguage: map[string]*CategoryStats{
			"go": {Total: 5, Vulnerable: 4, DetectionRate: 0.8},
		},
	}

	table := FormatTable(report)

	if !strings.Contains(table, "ProductSecBench") {
		t.Error("table should contain 'ProductSecBench' header")
	}
	if !strings.Contains(table, "test-model") {
		t.Error("table should contain model name")
	}
	if !strings.Contains(table, "72.5") {
		t.Error("table should contain PSB score")
	}
	if !strings.Contains(table, "CRITICAL") {
		t.Error("table should contain severity distribution")
	}
}

// TestFormatJSON verifies JSON output is valid and contains key fields.
func TestFormatJSON(t *testing.T) {
	report := ModelReport{
		Model:        "test-model",
		TotalSamples: 5,
		PSBScore:     50.0,
		BySeverity:   map[string]int{},
		ByOWASP:      map[string]*CategoryStats{},
		ByLanguage:   map[string]*CategoryStats{},
	}

	jsonStr, err := FormatJSON(report)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	if !strings.Contains(jsonStr, `"model": "test-model"`) {
		t.Error("JSON should contain model name")
	}
	if !strings.Contains(jsonStr, `"psb_score": 50`) {
		t.Error("JSON should contain PSB score")
	}
}

// TestFormatCSV verifies CSV output structure.
func TestFormatCSV(t *testing.T) {
	report := ModelReport{
		Model: "test-model",
		Results: []EvalResult{
			{
				PromptID:           "p1",
				Language:           "go",
				VulnerabilityFound: true,
				SeverityMaxLabel:   "HIGH",
				FindingCount:       2,
				SeverityScore:      14.0,
				CWEMatched:         true,
				OWASPMatched:       true,
				RuleIDs:            []string{"BATOU-INJ-001", "BATOU-INJ-002"},
			},
		},
	}

	csv := FormatCSV(report)
	lines := strings.Split(strings.TrimSpace(csv), "\n")

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines (header + data), got %d", len(lines))
	}

	if !strings.Contains(lines[0], "prompt_id") {
		t.Error("CSV header should contain 'prompt_id'")
	}

	if !strings.Contains(lines[1], "BATOU-INJ-001;BATOU-INJ-002") {
		t.Errorf("CSV data should contain rule IDs, got: %s", lines[1])
	}
}

// TestCompareModels verifies cross-model comparison.
func TestCompareModels(t *testing.T) {
	reports := []ModelReport{
		{Model: "model-a", PSBScore: 80.0, VulnerabilityRate: 0.9, F1: 0.85, TotalSamples: 10},
		{Model: "model-b", PSBScore: 60.0, VulnerabilityRate: 0.7, F1: 0.65, TotalSamples: 10},
	}

	cr := CompareModels(reports)

	if len(cr.Summary) != 2 {
		t.Fatalf("expected 2 models in summary, got %d", len(cr.Summary))
	}

	// model-a should rank first (higher PSB score)
	if cr.Summary[0].Model != "model-a" {
		t.Errorf("expected model-a ranked first, got %s", cr.Summary[0].Model)
	}

	table := FormatComparisonTable(cr)
	if !strings.Contains(table, "model-a") || !strings.Contains(table, "model-b") {
		t.Error("comparison table should contain both model names")
	}
}

// TestScanCode verifies the convenience ScanCode function.
func TestScanCode(t *testing.T) {
	code := loadTestFixture(t, "vuln_go_sqli_short.go.txt")
	findings := ScanCode(code, "go")
	if len(findings) == 0 {
		t.Error("expected findings for SQL injection in Go")
	}
}

// TestMatchesCWE verifies CWE matching logic.
func TestMatchesCWE(t *testing.T) {
	tests := []struct {
		expected []string
		found    string
		want     bool
	}{
		{[]string{"CWE-89"}, "CWE-89", true},
		{[]string{"CWE-89"}, "89", true},
		{[]string{"89"}, "CWE-89", true},
		{[]string{"CWE-79"}, "CWE-89", false},
		{[]string{}, "CWE-89", false},
	}

	for _, tt := range tests {
		got := matchesCWE(tt.expected, tt.found)
		if got != tt.want {
			t.Errorf("matchesCWE(%v, %q) = %v, want %v", tt.expected, tt.found, got, tt.want)
		}
	}
}

// TestMatchesOWASP verifies OWASP matching logic.
func TestMatchesOWASP(t *testing.T) {
	tests := []struct {
		expected string
		found    string
		want     bool
	}{
		{"A03", "A03:2021-Injection", true},
		{"A03", "A03", true},
		{"A01", "A03:2021-Injection", false},
		{"", "A03", false},
		{"A03", "", false},
	}

	for _, tt := range tests {
		got := matchesOWASP(tt.expected, tt.found)
		if got != tt.want {
			t.Errorf("matchesOWASP(%q, %q) = %v, want %v", tt.expected, tt.found, got, tt.want)
		}
	}
}

func floatAbs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
