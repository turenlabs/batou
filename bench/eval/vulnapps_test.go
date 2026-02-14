package eval

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// TestVulnApps_WebGoat verifies GTSS detects all WebGoat vulnerability patterns.
func TestVulnApps_WebGoat(t *testing.T) {
	tests := []struct {
		name        string
		fixture     string
		expectRules []string // at least one of these must fire
	}{
		{
			name:        "WebGoat SQL Injection",
			fixture:     "java/vulnerable/webgoat_sqli.java",
			expectRules: []string{"GTSS-INJ-001"},
		},
		{
			name:        "WebGoat XSS",
			fixture:     "java/vulnerable/webgoat_xss.java",
			expectRules: []string{"GTSS-XSS-014", "GTSS-XSS-015"},
		},
		{
			name:        "WebGoat XXE",
			fixture:     "java/vulnerable/webgoat_xxe.java",
			expectRules: []string{"GTSS-GEN-003"},
		},
		{
			name:        "WebGoat Insecure Deserialization",
			fixture:     "java/vulnerable/webgoat_deserialization.java",
			expectRules: []string{"GTSS-GEN-002"},
		},
		{
			name:        "WebGoat Path Traversal",
			fixture:     "java/vulnerable/webgoat_path_traversal.java",
			expectRules: []string{"GTSS-TRV-001"},
		},
		{
			name:        "WebGoat SSRF",
			fixture:     "java/vulnerable/webgoat_ssrf.java",
			expectRules: []string{"GTSS-SSRF-001"},
		},
		{
			name:        "WebGoat JWT Hardcoded Key",
			fixture:     "java/vulnerable/webgoat_jwt.java",
			expectRules: []string{"GTSS-CRY-012"},
		},
		{
			name:        "WebGoat Insecure Logging",
			fixture:     "java/vulnerable/webgoat_insecure_logging.java",
			expectRules: []string{"GTSS-LOG-002", "GTSS-LOG-003"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			if len(result.Findings) == 0 {
				t.Fatalf("expected findings for %s but got none", tt.name)
			}
			for _, ruleID := range tt.expectRules {
				testutil.MustFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_WebGoat_Safe verifies fixed WebGoat patterns do not trigger injection/XSS rules.
func TestVulnApps_WebGoat_Safe(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		denyRules  []string // these must NOT fire
	}{
		{
			name:      "WebGoat SQLi Fixed",
			fixture:   "java/safe/webgoat_sqli_fixed.java",
			denyRules: []string{"GTSS-INJ-001"},
		},
		{
			name:      "WebGoat XSS Fixed",
			fixture:   "java/safe/webgoat_xss_fixed.java",
			denyRules: []string{"GTSS-XSS-014", "GTSS-XSS-015"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			for _, ruleID := range tt.denyRules {
				testutil.MustNotFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_JuiceShop verifies GTSS detects all Juice Shop vulnerability patterns.
func TestVulnApps_JuiceShop(t *testing.T) {
	tests := []struct {
		name        string
		fixture     string
		expectRules []string
	}{
		{
			name:        "Juice Shop SQL Injection via Sequelize",
			fixture:     "javascript/vulnerable/juiceshop_sqli.js",
			expectRules: []string{"GTSS-INJ-001"},
		},
		{
			name:        "Juice Shop NoSQL Injection",
			fixture:     "javascript/vulnerable/juiceshop_nosql.js",
			expectRules: []string{"GTSS-INJ-007"},
		},
		{
			name:        "Juice Shop XSS",
			fixture:     "javascript/vulnerable/juiceshop_xss.js",
			expectRules: []string{"GTSS-VAL-001"}, // taint also catches document.write
		},
		{
			name:        "Juice Shop JWT None Algorithm",
			fixture:     "javascript/vulnerable/juiceshop_jwt.js",
			expectRules: []string{"GTSS-CRY-012"},
		},
		{
			name:        "Juice Shop Insecure Deserialization",
			fixture:     "javascript/vulnerable/juiceshop_deserialization.js",
			expectRules: []string{"GTSS-GEN-002", "GTSS-INJ-003"},
		},
		{
			name:        "Juice Shop Directory Traversal",
			fixture:     "javascript/vulnerable/juiceshop_traversal.js",
			expectRules: []string{"GTSS-TRV-007"},
		},
		{
			name:        "Juice Shop SSRF",
			fixture:     "javascript/vulnerable/juiceshop_ssrf.js",
			expectRules: []string{"GTSS-SSRF-001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			if len(result.Findings) == 0 {
				t.Fatalf("expected findings for %s but got none", tt.name)
			}
			for _, ruleID := range tt.expectRules {
				testutil.MustFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_JuiceShop_Safe verifies fixed Juice Shop patterns pass cleanly.
func TestVulnApps_JuiceShop_Safe(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		denyRules []string
	}{
		{
			name:      "Juice Shop SQLi Fixed",
			fixture:   "javascript/safe/juiceshop_sqli_fixed.js",
			denyRules: []string{"GTSS-INJ-001"},
		},
		{
			name:      "Juice Shop JWT Fixed",
			fixture:   "javascript/safe/juiceshop_jwt_fixed.js",
			denyRules: []string{"GTSS-JSTS-006", "GTSS-CRY-012"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			for _, ruleID := range tt.denyRules {
				testutil.MustNotFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_DVWA verifies GTSS detects all DVWA vulnerability patterns.
func TestVulnApps_DVWA(t *testing.T) {
	tests := []struct {
		name        string
		fixture     string
		expectRules []string
	}{
		{
			name:        "DVWA Command Injection",
			fixture:     "php/vulnerable/command_injection.php",
			expectRules: []string{"GTSS-INJ-002"},
		},
		{
			name:        "DVWA SQL Injection",
			fixture:     "php/vulnerable/dvwa_sqli.php",
			expectRules: []string{"GTSS-INJ-001"},
		},
		{
			name:        "DVWA File Inclusion",
			fixture:     "php/vulnerable/dvwa_file_inclusion.php",
			expectRules: []string{"GTSS-TRV-002"},
		},
		{
			name:        "DVWA XSS",
			fixture:     "php/vulnerable/dvwa_xss.php",
			expectRules: []string{"GTSS-XSS-011"},
		},
		{
			name:        "DVWA Weak Session",
			fixture:     "php/vulnerable/dvwa_weak_session.php",
			expectRules: []string{"GTSS-AUTH-006"},
		},
		{
			name:        "DVWA Open Redirect",
			fixture:     "php/vulnerable/dvwa_open_redirect.php",
			expectRules: []string{"GTSS-VAL-001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			if len(result.Findings) == 0 {
				t.Fatalf("expected findings for %s but got none", tt.name)
			}
			for _, ruleID := range tt.expectRules {
				testutil.MustFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_DVWA_Safe verifies fixed DVWA patterns do not trigger critical rules.
func TestVulnApps_DVWA_Safe(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		denyRules []string
	}{
		{
			name:      "DVWA SQLi Fixed",
			fixture:   "php/safe/dvwa_sqli_fixed.php",
			denyRules: []string{"GTSS-INJ-001", "GTSS-PHP-006"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			for _, ruleID := range tt.denyRules {
				testutil.MustNotFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_RailsGoat verifies GTSS detects all RailsGoat vulnerability patterns.
func TestVulnApps_RailsGoat(t *testing.T) {
	tests := []struct {
		name        string
		fixture     string
		expectRules []string
	}{
		{
			name:        "RailsGoat Mass Assignment",
			fixture:     "ruby/vulnerable/railsgoat_mass_assignment.rb",
			expectRules: []string{"GTSS-GEN-007"},
		},
		{
			name:        "RailsGoat SQL Injection",
			fixture:     "ruby/vulnerable/railsgoat_sqli.rb",
			expectRules: []string{"GTSS-INJ-001"},
		},
		{
			name:        "RailsGoat Command Injection",
			fixture:     "ruby/vulnerable/railsgoat_command_injection.rb",
			expectRules: []string{"GTSS-INJ-002"},
		},
		{
			name:        "RailsGoat XSS",
			fixture:     "ruby/vulnerable/railsgoat_xss.rb",
			expectRules: []string{"GTSS-XSS-008"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			if len(result.Findings) == 0 {
				t.Fatalf("expected findings for %s but got none", tt.name)
			}
			for _, ruleID := range tt.expectRules {
				testutil.MustFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_RailsGoat_Safe verifies fixed RailsGoat patterns pass cleanly.
func TestVulnApps_RailsGoat_Safe(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		denyRules []string
	}{
		{
			name:      "RailsGoat Mass Assignment Fixed",
			fixture:   "ruby/safe/railsgoat_mass_assignment_fixed.rb",
			denyRules: []string{"GTSS-GEN-007", "GTSS-MASS-003", "GTSS-FW-RAILS-004"},
		},
		{
			name:      "RailsGoat SQLi Fixed",
			fixture:   "ruby/safe/railsgoat_sqli_fixed.rb",
			denyRules: []string{"GTSS-INJ-001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanFixture(t, tt.fixture)
			for _, ruleID := range tt.denyRules {
				testutil.MustNotFindRule(t, result, ruleID)
			}
		})
	}
}

// TestVulnApps_CoverageGaps documents known detection gaps for tracking.
func TestVulnApps_CoverageGaps(t *testing.T) {
	t.Log("=== VULN APP COVERAGE GAPS ===")
	t.Log("")
	t.Log("1. Juice Shop Prototype Pollution (juiceshop_prototype_pollution.js)")
	t.Log("   - Pattern: _.merge(config, req.body) / Object.assign(user, req.body)")
	t.Log("   - CWE-1321, OWASP A03")
	t.Log("   - Expected: GTSS-PROTO-001 or GTSS-PROTO-002")
	t.Log("   - Status: NOT DETECTED (prototype pollution rules may not match lodash.merge with req.body)")
	t.Log("")
	t.Log("2. DVWA File Upload (dvwa_file_upload.php)")
	t.Log("   - Pattern: move_uploaded_file without type/content validation")
	t.Log("   - CWE-434, OWASP A04")
	t.Log("   - Expected: file upload validation rule")
	t.Log("   - Status: NOT DETECTED (no rule for missing upload validation)")
	t.Log("")
	t.Log("3. RailsGoat Session Fixation (railsgoat_session_fixation.rb)")
	t.Log("   - Pattern: session[:user_id] = user.id without reset_session")
	t.Log("   - CWE-384, OWASP A07")
	t.Log("   - Expected: GTSS-AUTH-004")
	t.Log("   - Status: NOT DETECTED (session fixation rule needs Ruby-specific patterns)")
	t.Log("")
	t.Log("4. Juice Shop JWT None Algorithm (juiceshop_jwt.js)")
	t.Log("   - Pattern: jwt.verify(token, secret) without { algorithms: ['HS256'] }")
	t.Log("   - CWE-347, OWASP A02")
	t.Log("   - Expected: GTSS-JSTS-006 (fires on jwt.verify without algorithms option)")
	t.Log("   - Status: PARTIALLY DETECTED (GTSS-CRY-012 fires for hardcoded key, but GTSS-JSTS-006 did not)")
	t.Log("")
	t.Log("=== END GAPS ===")
}
