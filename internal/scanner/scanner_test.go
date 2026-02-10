package scanner_test

import (
	"strings"
	"testing"

	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/testutil"

	// Register all rule packages to trigger init() registrations.
	_ "github.com/turen/gtss/internal/rules/injection"
	_ "github.com/turen/gtss/internal/rules/secrets"
	_ "github.com/turen/gtss/internal/rules/crypto"
	_ "github.com/turen/gtss/internal/rules/xss"
	_ "github.com/turen/gtss/internal/rules/traversal"
	_ "github.com/turen/gtss/internal/rules/ssrf"
	_ "github.com/turen/gtss/internal/rules/auth"
	_ "github.com/turen/gtss/internal/rules/generic"
	_ "github.com/turen/gtss/internal/rules/logging"
	_ "github.com/turen/gtss/internal/rules/validation"
	_ "github.com/turen/gtss/internal/rules/memory"

	// Taint analysis engine and language catalogs.
	_ "github.com/turen/gtss/internal/taint"
	_ "github.com/turen/gtss/internal/taint/languages"
)

// ---------------------------------------------------------------------------
// Full integration: Scan vulnerable JS SQL injection fixture
// ---------------------------------------------------------------------------

func TestScanJSSQLInjection(t *testing.T) {
	code := `function search(req, res) {
	const term = req.query.q;
	const sql = "SELECT * FROM items WHERE name = '" + term + "'";
	db.query(sql);
}`
	result := testutil.ScanContent(t, "test.js", code)

	if testutil.CountFindings(result) == 0 {
		t.Error("expected findings for JS SQL injection, got none")
	}

	// Should have at least one injection-related finding.
	hasInjection := false
	for _, f := range result.Findings {
		if strings.Contains(f.RuleID, "INJ") || strings.Contains(f.RuleID, "TAINT") {
			hasInjection = true
			break
		}
	}
	if !hasInjection {
		t.Errorf("expected an injection or taint finding, got rule IDs: %v", testutil.FindingRuleIDs(result))
	}
}

// ---------------------------------------------------------------------------
// Full integration: Scan safe parameterized query
// ---------------------------------------------------------------------------

func TestScanSafeParameterizedQuery(t *testing.T) {
	code := `function search(req, res) {
	const term = req.query.q;
	db.query("SELECT * FROM items WHERE name = ?", [term]);
}`
	result := testutil.ScanContent(t, "test.js", code)

	// A parameterized query should not produce SQL injection findings from regex rules.
	for _, f := range result.Findings {
		if strings.Contains(f.RuleID, "INJ") && f.Severity >= rules.Critical {
			// Some regex rules might still fire but should not be Critical for
			// parameterized queries. Taint analysis might still detect the flow.
			// We check that at minimum the regex-based injection rule is not triggered.
			if !strings.Contains(f.RuleID, "TAINT") {
				t.Errorf("unexpected critical injection finding for parameterized query: %s", f.RuleID)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Critical findings set Blocked = true
// ---------------------------------------------------------------------------

func TestCriticalFindingsBlock(t *testing.T) {
	// This Go code has a clear SQL injection that should produce a Critical finding.
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	username := r.FormValue("username")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	defer rows.Close()
}`
	result := testutil.ScanContent(t, "test.go", code)

	if testutil.CountFindings(result) == 0 {
		t.Fatal("expected findings for SQL injection, got none")
	}

	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity >= rules.Critical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one Critical severity finding")
	}
	testutil.AssertBlocked(t, result)
}

// ---------------------------------------------------------------------------
// Multiple languages in sequence
// ---------------------------------------------------------------------------

func TestMultipleLanguagesSequential(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		code     string
		wantFind bool // expect at least one finding
	}{
		{
			name: "Go SQL injection",
			file: "test.go",
			code: `func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	q := fmt.Sprintf("SELECT * FROM t WHERE n='%s'", name)
	db.Query(q)
}`,
			wantFind: true,
		},
		{
			name: "Python command injection",
			file: "test.py",
			code: `import os
def run(request):
    cmd = request.args.get("cmd")
    os.system(cmd)
`,
			wantFind: true,
		},
		{
			name: "JavaScript XSS",
			file: "test.js",
			code: `function render(req, res) {
	const name = req.query.name;
	res.send("<h1>" + name + "</h1>");
}`,
			wantFind: true,
		},
		{
			name: "Java SQL injection",
			file: "Test.java",
			code: `public void search(HttpServletRequest req, HttpServletResponse resp) {
	String user = req.getParameter("user");
	String sql = "SELECT * FROM users WHERE name = '" + user + "'";
	stmt.executeQuery(sql);
}`,
			wantFind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testutil.ScanContent(t, tt.file, tt.code)
			if tt.wantFind && testutil.CountFindings(result) == 0 {
				t.Errorf("expected findings for %s, got none", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan safe Go code produces no findings
// ---------------------------------------------------------------------------

func TestScanSafeGoCode(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	username := r.FormValue("username")
	row := db.QueryRow("SELECT id, email FROM users WHERE username = $1", username)
	var id int
	var email string
	if err := row.Scan(&id, &email); err != nil {
		http.Error(w, "not found", 404)
		return
	}
	fmt.Fprintf(w, "ID: %d, Email: %s\n", id, email)
}`
	result := testutil.ScanContent(t, "test.go", code)

	// Parameterized queries should not produce critical injection findings.
	for _, f := range result.Findings {
		if f.Severity >= rules.Critical && strings.Contains(f.RuleID, "INJ") {
			t.Errorf("unexpected critical injection finding in safe code: %s - %s", f.RuleID, f.Title)
		}
	}
	testutil.AssertNotBlocked(t, result)
}

// ---------------------------------------------------------------------------
// Scan fixture files if they exist
// ---------------------------------------------------------------------------

func TestScanGoFixtures(t *testing.T) {
	vulnFixtures := testutil.VulnerableFixtures(t, "go")
	if len(vulnFixtures) == 0 {
		t.Skip("no Go vulnerable fixtures available")
	}

	for name, content := range vulnFixtures {
		t.Run("vulnerable/"+name, func(t *testing.T) {
			result := testutil.ScanContent(t, "test.go", content)
			if testutil.CountFindings(result) == 0 {
				t.Errorf("expected findings in vulnerable fixture %s, got none", name)
			}
		})
	}

	safeFixtures := testutil.SafeFixtures(t, "go")
	for name, content := range safeFixtures {
		t.Run("safe/"+name, func(t *testing.T) {
			result := testutil.ScanContent(t, "test.go", content)
			// Safe fixtures should not be blocked.
			if result.Blocked {
				criticalIDs := []string{}
				for _, f := range result.Findings {
					if f.Severity >= rules.Critical {
						criticalIDs = append(criticalIDs, f.RuleID)
					}
				}
				t.Errorf("safe fixture %s was blocked; critical findings: %v", name, criticalIDs)
			}
		})
	}
}
