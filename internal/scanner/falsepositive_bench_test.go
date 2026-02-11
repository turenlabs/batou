package scanner_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/testutil"

	// Register all rule packages.
	_ "github.com/turen/gtss/internal/rules/auth"
	_ "github.com/turen/gtss/internal/rules/crypto"
	_ "github.com/turen/gtss/internal/rules/generic"
	_ "github.com/turen/gtss/internal/rules/injection"
	_ "github.com/turen/gtss/internal/rules/logging"
	_ "github.com/turen/gtss/internal/rules/memory"
	_ "github.com/turen/gtss/internal/rules/secrets"
	_ "github.com/turen/gtss/internal/rules/ssrf"
	_ "github.com/turen/gtss/internal/rules/traversal"
	_ "github.com/turen/gtss/internal/rules/validation"
	_ "github.com/turen/gtss/internal/rules/xss"

	// Taint catalogs.
	_ "github.com/turen/gtss/internal/taint"
	_ "github.com/turen/gtss/internal/taint/languages"
)

// langToFakePath maps bench language directory names to synthetic non-test
// file paths. Using non-test paths ensures fpfilter.IsTestFile does not
// reduce severity, giving us accurate false-positive measurements.
var langToFakePath = map[string]string{
	"go":         "/app/handler.go",
	"javascript": "/app/handler.ts",
	"python":     "/app/handler.py",
	"java":       "/app/Handler.java",
	"php":        "/app/handler.php",
	"ruby":       "/app/handler.rb",
}

// ruleCategory extracts the category prefix from a rule ID.
// E.g., "GTSS-INJ-001" -> "INJ", "GTSS-TAINT-sql_query" -> "TAINT".
func ruleCategory(ruleID string) string {
	parts := strings.Split(ruleID, "-")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ruleID
}

type fpEntry struct {
	fixture string
	ruleID  string
	title   string
	sev     rules.Severity
	line    int
	lang    string
}

// TestFalsePositiveBench scans every safe bench fixture through the full
// scanner pipeline and reports any false positives (findings with severity
// above Low on code that is intentionally safe).
//
// This test logs false positives as informational data rather than test
// failures. It serves as a measurement tool for GTSS's false-positive rate.
func TestFalsePositiveBench(t *testing.T) {
	fixtures := testutil.BenchSafeFixtures(t)
	if len(fixtures) == 0 {
		t.Skip("no bench safe fixtures found")
	}

	var totalFixtures int
	var totalFindings int
	var fpCount int

	var fps []fpEntry
	langFixtures := make(map[string]int)
	langFPs := make(map[string]int)
	categoryFPs := make(map[string]int)

	for _, fix := range fixtures {
		fakePath, ok := langToFakePath[fix.Lang]
		if !ok {
			ext := filepath.Ext(fix.FileName)
			fakePath = "/app/handler" + ext
		}

		t.Run(fix.Lang+"/"+fix.FileName, func(t *testing.T) {
			result := testutil.ScanContent(t, fakePath, fix.Content)
			totalFixtures++
			langFixtures[fix.Lang]++
			totalFindings += len(result.Findings)

			for _, f := range result.Findings {
				if f.Severity > rules.Low {
					fpCount++
					langFPs[fix.Lang]++
					categoryFPs[ruleCategory(f.RuleID)]++
					fps = append(fps, fpEntry{
						fixture: fix.Lang + "/" + fix.FileName,
						ruleID:  f.RuleID,
						title:   f.Title,
						sev:     f.Severity,
						line:    f.LineNumber,
						lang:    fix.Lang,
					})
					t.Logf("FP: %s severity %s at line %d: %s",
						f.RuleID, f.Severity, f.LineNumber, f.Title)
				}
			}
		})
	}

	// Overall summary
	t.Logf("")
	t.Logf("=== False-Positive Benchmark Summary ===")
	t.Logf("Safe fixtures scanned: %d", totalFixtures)
	t.Logf("Total findings:        %d", totalFindings)
	t.Logf("False positives (>Low): %d", fpCount)
	if totalFixtures > 0 {
		t.Logf("FP rate per fixture:   %.1f%%", float64(fpCount)/float64(totalFixtures)*100)
	}

	// Per-language breakdown
	t.Logf("")
	t.Logf("--- Per-Language FP Rates ---")
	langs := sortedKeys(langFixtures)
	for _, lang := range langs {
		count := langFixtures[lang]
		fp := langFPs[lang]
		t.Logf("  %-12s %d fixtures, %d FPs (%.0f%%)", lang, count, fp,
			safePercent(fp, count))
	}

	// Per-rule-category breakdown
	t.Logf("")
	t.Logf("--- Per-Rule-Category FP Counts ---")
	cats := sortedKeys(categoryFPs)
	for _, cat := range cats {
		t.Logf("  %-12s %d", cat, categoryFPs[cat])
	}

	// Detailed list
	if len(fps) > 0 {
		t.Logf("")
		t.Logf("--- All False Positives ---")
		for _, fp := range fps {
			t.Logf("  [%s] %s line %d: %s (%s)",
				fp.sev, fp.fixture, fp.line, fp.ruleID, fp.title)
		}
	}
}

// TestFalsePositiveBenchNotBlocked verifies that no safe fixture triggers
// a write-blocking result (Critical severity). Safe code should NEVER be
// blocked, so this is a hard test failure.
func TestFalsePositiveBenchNotBlocked(t *testing.T) {
	fixtures := testutil.BenchSafeFixtures(t)
	if len(fixtures) == 0 {
		t.Skip("no bench safe fixtures found")
	}

	for _, fix := range fixtures {
		fakePath, ok := langToFakePath[fix.Lang]
		if !ok {
			ext := filepath.Ext(fix.FileName)
			fakePath = "/app/handler" + ext
		}

		t.Run(fix.Lang+"/"+fix.FileName, func(t *testing.T) {
			result := testutil.ScanContent(t, fakePath, fix.Content)
			if result.Blocked {
				var criticals []string
				for _, f := range result.Findings {
					if f.Severity >= rules.Critical {
						criticals = append(criticals, fmt.Sprintf("%s (line %d)", f.RuleID, f.LineNumber))
					}
				}
				t.Errorf("safe fixture BLOCKED by: %s", strings.Join(criticals, ", "))
			}
		})
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func safePercent(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) / float64(denom) * 100
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
