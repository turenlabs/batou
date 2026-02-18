package scanner_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/testutil"

	// Register all rule packages.
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

// ---------------------------------------------------------------------------
// Fixture-to-rule mapping for OWASP-style JavaScript vulnerabilities
// ---------------------------------------------------------------------------

type vulnFixture struct {
	file     string   // relative path under testdata/fixtures/
	owasp    string   // OWASP Top 10 category
	cwe      int      // CWE number
	prefixes []string // acceptable BATOU-* rule ID prefixes
}

var jsVulnFixtures = []vulnFixture{
	{"javascript/vulnerable/app_sqli.js", "A03", 89, []string{"BATOU-INJ", "BATOU-TAINT-sql"}},
	{"javascript/vulnerable/app_xss.js", "A03", 79, []string{"BATOU-XSS", "BATOU-TAINT-html"}},
	{"javascript/vulnerable/app_nosql.js", "A03", 943, []string{"BATOU-NOSQL", "BATOU-INJ-007"}},
	{"javascript/vulnerable/app_jwt.js", "A02", 347, []string{"BATOU-SEC", "BATOU-AUTH"}},
	{"javascript/vulnerable/app_ssrf.js", "A10", 918, []string{"BATOU-SSRF", "BATOU-TAINT-url"}},
	{"javascript/vulnerable/app_traversal.js", "A01", 22, []string{"BATOU-TRV", "BATOU-TAINT-file"}},
	{"javascript/vulnerable/app_deserialization.js", "A08", 502, []string{"BATOU-GEN-002", "BATOU-DESER", "BATOU-TAINT-deserialize", "BATOU-TAINT-code_eval"}},
	{"javascript/vulnerable/app_prototype_pollution.js", "A03", 1321, []string{"BATOU-PROTO"}},
}

var jsSafeFixtures = []string{
	"javascript/safe/app_sqli_fixed.js",
	"javascript/safe/app_jwt_fixed.js",
}

// ---------------------------------------------------------------------------
// Fixture-to-rule mapping for OWASP-style Java vulnerabilities
// ---------------------------------------------------------------------------

var javaVulnFixtures = []vulnFixture{
	{"java/vulnerable/app_sqli.java", "A03", 89, []string{"BATOU-INJ", "BATOU-TAINT-sql"}},
	{"java/vulnerable/app_xss.java", "A03", 79, []string{"BATOU-XSS", "BATOU-TAINT-html"}},
	{"java/vulnerable/app_xxe.java", "A05", 611, []string{"BATOU-XXE", "BATOU-INJ"}},
	{"java/vulnerable/app_jwt.java", "A02", 347, []string{"BATOU-SEC", "BATOU-AUTH"}},
	{"java/vulnerable/app_ssrf.java", "A10", 918, []string{"BATOU-SSRF", "BATOU-TAINT-url"}},
	{"java/vulnerable/app_path_traversal.java", "A01", 22, []string{"BATOU-TRV", "BATOU-TAINT-file"}},
	{"java/vulnerable/app_deserialization.java", "A08", 502, []string{"BATOU-GEN-002", "BATOU-DESER", "BATOU-JAVAAST-003"}},
	{"java/vulnerable/app_insecure_logging.java", "A09", 117, []string{"BATOU-LOG", "BATOU-TAINT-log"}},
}

var javaSafeFixtures = []string{
	"java/safe/app_sqli_fixed.java",
	"java/safe/app_xss_fixed.java",
}

// ---------------------------------------------------------------------------
// Helper: check if any fired rule ID matches any acceptable prefix
// ---------------------------------------------------------------------------

func matchesAnyPrefix(firedIDs []string, prefixes []string) bool {
	for _, fired := range firedIDs {
		upper := strings.ToUpper(fired)
		for _, prefix := range prefixes {
			if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
				return true
			}
		}
	}
	return false
}

// syntheticPath returns a non-test file path with the correct extension
// for language detection, avoiding isTestFile() confidence capping.
func syntheticPath(fixturePath string) string {
	ext := filepath.Ext(fixturePath)
	switch ext {
	case ".java":
		return "/app/Target.java"
	default:
		return "/app/target" + ext
	}
}

// ---------------------------------------------------------------------------
// TestJSApp_Detection — table-driven detection for 8 JS fixtures
// ---------------------------------------------------------------------------

func TestJSApp_Detection(t *testing.T) {
	for _, tc := range jsVulnFixtures {
		tc := tc
		name := filepath.Base(tc.file)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tc.file)
			result := testutil.ScanContent(t, syntheticPath(tc.file), content)

			ids := testutil.FindingRuleIDs(result)
			if !matchesAnyPrefix(ids, tc.prefixes) {
				t.Errorf("fixture %s (CWE-%d, %s): no finding matched prefixes %v; fired: %v",
					name, tc.cwe, tc.owasp, tc.prefixes, ids)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestJavaApp_Detection — table-driven detection for 8 Java fixtures
// ---------------------------------------------------------------------------

func TestJavaApp_Detection(t *testing.T) {
	for _, tc := range javaVulnFixtures {
		tc := tc
		name := filepath.Base(tc.file)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, tc.file)
			result := testutil.ScanContent(t, syntheticPath(tc.file), content)

			ids := testutil.FindingRuleIDs(result)
			if !matchesAnyPrefix(ids, tc.prefixes) {
				t.Errorf("fixture %s (CWE-%d, %s): no finding matched prefixes %v; fired: %v",
					name, tc.cwe, tc.owasp, tc.prefixes, ids)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestJSApp_SafeNotBlocked — safe JS fixtures must not block
// ---------------------------------------------------------------------------

func TestJSApp_SafeNotBlocked(t *testing.T) {
	for _, fix := range jsSafeFixtures {
		fix := fix
		name := filepath.Base(fix)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, fix)
			result := testutil.ScanContent(t, syntheticPath(fix), content)

			testutil.AssertNotBlocked(t, result)
			if n := testutil.CountBySeverityLabel(result, "critical"); n > 0 {
				t.Errorf("safe fixture %s produced %d critical finding(s); expected none", name, n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestJavaApp_SafeNotBlocked — safe Java fixtures must not block
// ---------------------------------------------------------------------------

func TestJavaApp_SafeNotBlocked(t *testing.T) {
	for _, fix := range javaSafeFixtures {
		fix := fix
		name := filepath.Base(fix)
		t.Run(name, func(t *testing.T) {
			content := testutil.LoadFixture(t, fix)
			result := testutil.ScanContent(t, syntheticPath(fix), content)

			testutil.AssertNotBlocked(t, result)
			if n := testutil.CountBySeverityLabel(result, "critical"); n > 0 {
				t.Errorf("safe fixture %s produced %d critical finding(s); expected none", name, n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestRealWorld_DetectionMatrix — combined matrix for all 16 vulnerable fixtures
// ---------------------------------------------------------------------------

func TestRealWorld_DetectionMatrix(t *testing.T) {
	type matrixRow struct {
		source  string
		fixture vulnFixture
	}

	var rows []matrixRow
	for _, f := range jsVulnFixtures {
		rows = append(rows, matrixRow{"JS", f})
	}
	for _, f := range javaVulnFixtures {
		rows = append(rows, matrixRow{"Java", f})
	}

	detected := 0
	total := len(rows)

	t.Logf("\n=== Real-World Detection Matrix ===")
	t.Logf("%-10s | %-40s | %-5s | %-8s | %s",
		"Source", "Fixture", "OWASP", "Detected", "Rule IDs")
	t.Logf("%-10s-+-%-40s-+-%-5s-+-%-8s-+-%s",
		strings.Repeat("-", 10),
		strings.Repeat("-", 40),
		strings.Repeat("-", 5),
		strings.Repeat("-", 8),
		strings.Repeat("-", 30))

	for _, row := range rows {
		name := filepath.Base(row.fixture.file)
		content := testutil.LoadFixture(t, row.fixture.file)
		result := testutil.ScanContent(t, syntheticPath(row.fixture.file), content)

		ids := testutil.FindingRuleIDs(result)
		hit := matchesAnyPrefix(ids, row.fixture.prefixes)

		status := "NO"
		if hit {
			status = "YES"
			detected++
		}

		t.Logf("%-10s | %-40s | %-5s | %8s | %s",
			row.source, name, row.fixture.owasp, status, strings.Join(ids, ", "))
	}

	rate := float64(detected) / float64(total) * 100
	t.Logf("---")
	t.Logf("Total: %d fixtures | Detected: %d | Missed: %d | Rate: %.0f%%",
		total, detected, total-detected, rate)

	// Log missed fixtures as errors so CI catches regressions.
	for _, row := range rows {
		name := filepath.Base(row.fixture.file)
		content := testutil.LoadFixture(t, row.fixture.file)
		result := testutil.ScanContent(t, syntheticPath(row.fixture.file), content)

		ids := testutil.FindingRuleIDs(result)
		if !matchesAnyPrefix(ids, row.fixture.prefixes) {
			t.Errorf("MISSED: %s/%s (CWE-%d, %s) — expected prefixes %v, got %v",
				row.source, name, row.fixture.cwe, row.fixture.owasp,
				row.fixture.prefixes, ids)
		}
	}

	// Summary line visible without -v.
	fmt.Printf("Real-world detection: %d/%d (%.0f%%)\n", detected, total, rate)
}
