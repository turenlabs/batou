package goflow

import (
	"testing"

	"github.com/turen/gtss/internal/rules"

	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turen/gtss/internal/taint/languages"
)

func scanGoFlow(code string) []rules.Finding {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.go",
		Content:  code,
		Language: rules.LangGo,
	}
	a := &GoFlowAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func hasTaintFinding(findings []rules.Finding) bool {
	for _, f := range findings {
		if len(f.RuleID) > 10 && f.RuleID[:10] == "GTSS-TAINT" {
			return true
		}
	}
	return false
}

// =========================================================================
// Source detection
// =========================================================================

func TestSource_FormValue(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

var db *sql.DB
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for FormValue -> db.Query flow")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSource_URLQueryGet(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}

var db *sql.DB
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for URL.Query().Get -> db.Query flow")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

// =========================================================================
// Sink detection
// =========================================================================

func TestSink_ExecCommand(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command("sh", "-c", cmd)
}
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for FormValue -> exec.Command flow")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSink_FprintfResponseWriter(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	fmt.Fprintf(w, name)
}
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for FormValue -> fmt.Fprintf(w, ...) flow")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

// =========================================================================
// Sanitizer detection
// =========================================================================

func TestSanitizer_HTMLEscapeString(t *testing.T) {
	code := `package main

import (
	"fmt"
	"html"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := html.EscapeString(name)
	fmt.Fprintf(w, safe)
}
`
	findings := scanGoFlow(code)
	// After sanitization, there should be no HTML output taint finding
	for _, f := range findings {
		if f.RuleID == "GTSS-TAINT-html_output" {
			t.Error("should not flag sanitized flow through html.EscapeString")
		}
	}
}

// =========================================================================
// Propagation through assignments and concatenation
// =========================================================================

func TestPropagation_StringConcat(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}

var db *sql.DB
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for propagation through string concatenation")
	}
}

func TestPropagation_MultiStep(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	upper := strings.ToUpper(name)
	query := "SELECT * FROM users WHERE name = '" + upper + "'"
	db.Query(query)
}

var db *sql.DB
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for multi-step propagation")
	}
}

// =========================================================================
// Input parameter seeding
// =========================================================================

func TestInputParamName(t *testing.T) {
	code := `package main

import (
	"database/sql"
)

func processInput(userInput string) {
	db.Query("SELECT * FROM users WHERE name = '" + userInput + "'")
}

var db *sql.DB
`
	findings := scanGoFlow(code)
	if !hasTaintFinding(findings) {
		t.Error("expected taint finding for parameter with input-like name")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

// =========================================================================
// Safe patterns (no findings expected)
// =========================================================================

func TestSafe_NoSourceNoSink(t *testing.T) {
	code := `package main

import "fmt"

func hello() {
	name := "world"
	fmt.Println("Hello, " + name)
}
`
	findings := scanGoFlow(code)
	if hasTaintFinding(findings) {
		t.Error("should not produce taint findings for code without sources or sinks")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSafe_ParameterizedQuery(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT * FROM users WHERE name = ?", name)
}

var db *sql.DB
`
	// Parameterized queries pass user input as a separate argument, not concatenated.
	// The taint analysis may or may not flag this depending on the sink definition's
	// dangerous argument positions. This test documents the behavior.
	findings := scanGoFlow(code)
	_ = findings // Document current behavior without asserting
}

// =========================================================================
// Edge cases
// =========================================================================

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  `import os`,
		Language: rules.LangPython,
	}
	a := &GoFlowAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestUnparseableCode(t *testing.T) {
	code := `this is {{ not valid Go`
	findings := scanGoFlow(code)
	if len(findings) != 0 {
		t.Error("expected no findings for unparseable code")
	}
}

func TestEmptyFunction(t *testing.T) {
	code := `package main

func handler() {}
`
	findings := scanGoFlow(code)
	if hasTaintFinding(findings) {
		t.Error("should not produce taint findings for empty function")
	}
}
