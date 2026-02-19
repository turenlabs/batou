package scanner_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/testutil"

	// Register all rule packages to trigger init() registrations.
	_ "github.com/turenlabs/batou/internal/rules/auth"
	_ "github.com/turenlabs/batou/internal/rules/container"
	_ "github.com/turenlabs/batou/internal/rules/cors"
	_ "github.com/turenlabs/batou/internal/rules/crypto"
	_ "github.com/turenlabs/batou/internal/rules/csharp"
	_ "github.com/turenlabs/batou/internal/rules/deser"
	_ "github.com/turenlabs/batou/internal/rules/encoding"
	_ "github.com/turenlabs/batou/internal/rules/framework"
	_ "github.com/turenlabs/batou/internal/rules/generic"
	_ "github.com/turenlabs/batou/internal/rules/golang"
	_ "github.com/turenlabs/batou/internal/rules/graphql"
	_ "github.com/turenlabs/batou/internal/rules/groovy"
	_ "github.com/turenlabs/batou/internal/rules/header"
	_ "github.com/turenlabs/batou/internal/rules/injection"
	_ "github.com/turenlabs/batou/internal/rules/java"
	_ "github.com/turenlabs/batou/internal/rules/jsts"
	_ "github.com/turenlabs/batou/internal/rules/jwt"
	_ "github.com/turenlabs/batou/internal/rules/kotlin"
	_ "github.com/turenlabs/batou/internal/rules/logging"
	_ "github.com/turenlabs/batou/internal/rules/lua"
	_ "github.com/turenlabs/batou/internal/rules/massassign"
	_ "github.com/turenlabs/batou/internal/rules/memory"
	_ "github.com/turenlabs/batou/internal/rules/misconfig"
	_ "github.com/turenlabs/batou/internal/rules/nosql"
	_ "github.com/turenlabs/batou/internal/rules/oauth"
	_ "github.com/turenlabs/batou/internal/rules/perl"
	_ "github.com/turenlabs/batou/internal/rules/php"
	_ "github.com/turenlabs/batou/internal/rules/prototype"
	_ "github.com/turenlabs/batou/internal/rules/python"
	_ "github.com/turenlabs/batou/internal/rules/race"
	_ "github.com/turenlabs/batou/internal/rules/redirect"
	_ "github.com/turenlabs/batou/internal/rules/ruby"
	_ "github.com/turenlabs/batou/internal/rules/rust"
	_ "github.com/turenlabs/batou/internal/rules/secrets"
	_ "github.com/turenlabs/batou/internal/rules/session"
	_ "github.com/turenlabs/batou/internal/rules/ssrf"
	_ "github.com/turenlabs/batou/internal/rules/ssti"
	_ "github.com/turenlabs/batou/internal/rules/swift"
	_ "github.com/turenlabs/batou/internal/rules/traversal"
	_ "github.com/turenlabs/batou/internal/rules/upload"
	_ "github.com/turenlabs/batou/internal/rules/validation"
	_ "github.com/turenlabs/batou/internal/rules/websocket"
	_ "github.com/turenlabs/batou/internal/rules/xss"
	_ "github.com/turenlabs/batou/internal/rules/xxe"

	// Taint analysis engine and language catalogs.
	_ "github.com/turenlabs/batou/internal/taint"
	_ "github.com/turenlabs/batou/internal/taint/languages"
	_ "github.com/turenlabs/batou/internal/taintrule"
)

// langFixtureExt maps fixture directory names to synthetic file paths.
// We use non-test paths (e.g., /app/handler.go) to avoid isTestFile() exclusion.
var langFixtureExt = map[string]string{
	"go":         "/app/handler.go",
	"python":     "/app/handler.py",
	"java":       "/app/Handler.java",
	"javascript": "/app/handler.ts",
	"php":        "/app/handler.php",
	"ruby":       "/app/handler.rb",
	"c":          "/app/handler.c",
	"cpp":        "/app/handler.cpp",
	"csharp":     "/app/Handler.cs",
	"kotlin":     "/app/Handler.kt",
	"rust":       "/app/handler.rs",
	"swift":      "/app/handler.swift",
	"perl":       "/app/handler.pl",
	"lua":        "/app/handler.lua",
	"groovy":     "/app/handler.groovy",
}

// TestSafeFixtures_NotBlocked scans every safe fixture file across all
// languages and asserts that none of them trigger a block (i.e., no Critical
// finding with ConfidenceScore >= 0.7).
func TestSafeFixtures_NotBlocked(t *testing.T) {
	languages := []string{
		"go", "python", "java", "javascript", "php",
		"ruby", "c", "cpp", "csharp", "kotlin",
		"rust", "swift", "perl", "lua", "groovy",
	}

	for _, lang := range languages {
		fixtures := testutil.SafeFixtures(t, lang)
		if len(fixtures) == 0 {
			continue
		}

		synthPath, ok := langFixtureExt[lang]
		if !ok {
			t.Fatalf("no synthetic path defined for language %q", lang)
		}

		for name, content := range fixtures {
			t.Run(lang+"/"+name, func(t *testing.T) {
				result := testutil.ScanContent(t, synthPath, content)

				// Primary assertion: safe fixtures must never be blocked.
				testutil.AssertNotBlocked(t, result)

				// Secondary: no Critical findings should exist at all.
				for _, f := range result.Findings {
					if f.Severity >= rules.Critical && f.ConfidenceScore >= 0.7 {
						t.Errorf("safe fixture %s/%s has blocking finding: %s (severity=%s, confidence=%.2f, line=%d)",
							lang, name, f.RuleID, f.Severity, f.ConfidenceScore, f.LineNumber)
					}
				}
			})
		}
	}
}

// TestSafeFixtures_NoHighConfCritical verifies that newly-added safe fixtures
// produce zero high-confidence Critical findings (confidence >= 0.7). Low-
// confidence Critical regex hits are expected false positives in safe code and
// are already caught by the NotBlocked test above.
func TestSafeFixtures_NoHighConfCritical(t *testing.T) {
	newFixtures := []struct {
		fixturePath string
		synthPath   string
	}{
		{"go/safe/ssrf_safe.go", "/app/handler.go"},
		{"go/safe/log_safe.go", "/app/handler.go"},
		{"python/safe/ssrf_safe.py", "/app/handler.py"},
		{"python/safe/ssti_safe.py", "/app/handler.py"},
		{"python/safe/log_safe.py", "/app/handler.py"},
		{"java/safe/SsrfSafe.java", "/app/Handler.java"},
		{"java/safe/HeaderSafe.java", "/app/Handler.java"},
		{"php/safe/ssrf_safe.php", "/app/handler.php"},
	}

	for _, tt := range newFixtures {
		name := tt.fixturePath
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tt.fixturePath)
			result := testutil.ScanContent(t, tt.synthPath, content)

			for _, f := range result.Findings {
				if f.Severity >= rules.Critical && f.ConfidenceScore >= 0.7 {
					t.Errorf("safe fixture %s has high-confidence Critical finding: %s (confidence=%.2f, line=%d)",
						name, f.RuleID, f.ConfidenceScore, f.LineNumber)
				}
			}
		})
	}
}

// TestSafeGoFixtures_Specific tests the specific Go safe fixtures we created,
// ensuring they don't produce any injection, SSRF, or logging findings.
func TestSafeGoFixtures_Specific(t *testing.T) {
	tests := []struct {
		fixture   string
		notRuleID []string // rule ID substrings that should NOT appear
	}{
		{
			fixture:   "go/safe/command_safe.go",
			notRuleID: []string{"INJ-002", "INJ-003"},
		},
		{
			fixture:   "go/safe/ssrf_safe.go",
			notRuleID: []string{"SSRF-001"},
		},
		{
			fixture:   "go/safe/log_safe.go",
			notRuleID: []string{"LOG-001"},
		},
		{
			fixture:   "go/safe/path_safe.go",
			notRuleID: []string{"TRV-001"},
		},
		{
			fixture:   "go/safe/sqli_parameterized.go",
			notRuleID: []string{"INJ-001"},
		},
	}

	for _, tt := range tests {
		name := filepath.Base(tt.fixture)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tt.fixture)
			result := testutil.ScanContent(t, "/app/handler.go", content)

			testutil.AssertNotBlocked(t, result)

			for _, f := range result.Findings {
				if f.Severity >= rules.Critical {
					for _, substr := range tt.notRuleID {
						if strings.Contains(f.RuleID, substr) {
							t.Errorf("unexpected Critical finding %s (confidence=%.2f) in safe fixture %s",
								f.RuleID, f.ConfidenceScore, name)
						}
					}
				}
			}
		})
	}
}

// TestSafePythonFixtures_Specific tests the specific Python safe fixtures.
func TestSafePythonFixtures_Specific(t *testing.T) {
	tests := []struct {
		fixture   string
		notRuleID []string
	}{
		{
			fixture:   "python/safe/command_safe.py",
			notRuleID: []string{"INJ-002", "INJ-003"},
		},
		{
			fixture:   "python/safe/ssrf_safe.py",
			notRuleID: []string{"SSRF-001"},
		},
		{
			fixture:   "python/safe/ssti_safe.py",
			notRuleID: []string{"SSTI-001"},
		},
		{
			fixture:   "python/safe/log_safe.py",
			notRuleID: []string{},
		},
		{
			fixture:   "python/safe/sqli_parameterized.py",
			notRuleID: []string{"INJ-001"},
		},
	}

	for _, tt := range tests {
		name := filepath.Base(tt.fixture)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tt.fixture)
			result := testutil.ScanContent(t, "/app/handler.py", content)

			testutil.AssertNotBlocked(t, result)

			for _, f := range result.Findings {
				if f.Severity >= rules.Critical {
					for _, substr := range tt.notRuleID {
						if strings.Contains(f.RuleID, substr) {
							t.Errorf("unexpected Critical finding %s (confidence=%.2f) in safe fixture %s",
								f.RuleID, f.ConfidenceScore, name)
						}
					}
				}
			}
		})
	}
}

// TestSafeJavaFixtures_Specific tests the specific Java safe fixtures.
func TestSafeJavaFixtures_Specific(t *testing.T) {
	tests := []struct {
		fixture   string
		notRuleID []string
	}{
		{
			fixture:   "java/safe/CommandSafe.java",
			notRuleID: []string{"INJ-003"},
		},
		{
			fixture:   "java/safe/SsrfSafe.java",
			notRuleID: []string{"SSRF-001"},
		},
		{
			fixture:   "java/safe/HeaderSafe.java",
			notRuleID: []string{"HDR-001"},
		},
		{
			fixture:   "java/safe/LogSafe.java",
			notRuleID: []string{"LOG-001"},
		},
		{
			fixture:   "java/safe/SqliPrepared.java",
			notRuleID: []string{"INJ-001"},
		},
	}

	for _, tt := range tests {
		name := filepath.Base(tt.fixture)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tt.fixture)
			result := testutil.ScanContent(t, "/app/Handler.java", content)

			testutil.AssertNotBlocked(t, result)

			for _, f := range result.Findings {
				if f.Severity >= rules.Critical {
					for _, substr := range tt.notRuleID {
						if strings.Contains(f.RuleID, substr) {
							t.Errorf("unexpected Critical finding %s (confidence=%.2f) in safe fixture %s",
								f.RuleID, f.ConfidenceScore, name)
						}
					}
				}
			}
		})
	}
}

// TestSafePHPFixtures_Specific tests the specific PHP safe fixtures.
func TestSafePHPFixtures_Specific(t *testing.T) {
	tests := []struct {
		fixture   string
		notRuleID []string
	}{
		{
			fixture:   "php/safe/command_safe.php",
			notRuleID: []string{"INJ-002", "INJ-003"},
		},
		{
			fixture:   "php/safe/sqli_pdo.php",
			notRuleID: []string{"INJ-001"},
		},
		{
			fixture:   "php/safe/xss_escaped.php",
			notRuleID: []string{"XSS-001"},
		},
		{
			fixture:   "php/safe/ssrf_safe.php",
			notRuleID: []string{"SSRF-001"},
		},
	}

	for _, tt := range tests {
		name := filepath.Base(tt.fixture)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tt.fixture)
			result := testutil.ScanContent(t, "/app/handler.php", content)

			testutil.AssertNotBlocked(t, result)

			for _, f := range result.Findings {
				if f.Severity >= rules.Critical {
					for _, substr := range tt.notRuleID {
						if strings.Contains(f.RuleID, substr) {
							t.Errorf("unexpected Critical finding %s (confidence=%.2f) in safe fixture %s",
								f.RuleID, f.ConfidenceScore, name)
						}
					}
				}
			}
		})
	}
}
