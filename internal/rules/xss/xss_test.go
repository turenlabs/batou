package xss

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// --- GTSS-XSS-001: innerHTML Usage ---

func TestXSS001_InnerHTML_Dynamic(t *testing.T) {
	content := `element.innerHTML = userInput;`
	result := testutil.ScanContent(t, "/app/dom.js", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-001")
}

func TestXSS001_InnerHTML_Static_Safe(t *testing.T) {
	content := `element.innerHTML = "<br>";`
	result := testutil.ScanContent(t, "/app/dom.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-XSS-001")
}

// --- GTSS-XSS-002: dangerouslySetInnerHTML ---

func TestXSS002_DangerouslySet(t *testing.T) {
	content := `<div dangerouslySetInnerHTML={{ __html: userContent }} />`
	result := testutil.ScanContent(t, "/app/component.tsx", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-002")
}

// --- GTSS-XSS-003: document.write ---

func TestXSS003_DocumentWrite(t *testing.T) {
	content := `document.write("<h1>" + userInput + "</h1>");`
	result := testutil.ScanContent(t, "/app/page.js", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-003")
}

func TestXSS003_DocumentWrite_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/xss_dom.js")
	result := testutil.ScanContent(t, "/app/dom.js", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-003")
}

// --- GTSS-XSS-004: Unescaped Template Output ---

func TestXSS004_GoTemplateHTML(t *testing.T) {
	content := `output := template.HTML(userInput)`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-004")
}

func TestXSS004_JinjaSafe(t *testing.T) {
	content := `{{ user_bio | safe }}`
	result := testutil.ScanContent(t, "/app/templates/profile.py", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-004")
}

func TestXSS004_ERBRaw(t *testing.T) {
	content := `<%= raw(user_content) %>`
	result := testutil.ScanContent(t, "/app/views/show.rb", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-004")
}

func TestXSS004_PHPEcho(t *testing.T) {
	content := `<?php echo $user_name; ?>`
	result := testutil.ScanContent(t, "/app/view.php", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-004")
}

func TestXSS004_HandlebarsTriple(t *testing.T) {
	content := `{{{ user_bio }}}`
	result := testutil.ScanContent(t, "/app/template.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-004")
}

func TestXSS004_Safe_PHPHtmlspecialchars(t *testing.T) {
	content := `<?php echo htmlspecialchars($user_name); ?>`
	result := testutil.ScanContent(t, "/app/view.php", content)
	testutil.MustNotFindRule(t, result, "GTSS-XSS-004")
}

// --- GTSS-XSS-005: DOM Manipulation ---

func TestXSS005_SetAttribute(t *testing.T) {
	content := `element.setAttribute("href", userUrl);`
	result := testutil.ScanContent(t, "/app/dom.js", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-005")
}

// --- GTSS-XSS-006: Response Header Injection ---

func TestXSS006_NodeSetHeader(t *testing.T) {
	content := `res.setHeader('X-Custom', req.query.value);`
	result := testutil.ScanContent(t, "/app/middleware.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-006")
}

// --- GTSS-XSS-007: URL Scheme Injection ---

func TestXSS007_JSProtocol(t *testing.T) {
	content := `<a href="javascript:alert(1)">Click</a>`
	result := testutil.ScanContent(t, "/app/page.js", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-007")
}

func TestXSS007_JSProtocolConcat(t *testing.T) {
	content := `var link = "javascript:" + payload;`
	result := testutil.ScanContent(t, "/app/xss.js", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-007")
}

// --- GTSS-XSS-008: Server-Side Rendering XSS ---

func TestXSS008_PythonMarkup(t *testing.T) {
	content := `output = Markup(user_content)`
	result := testutil.ScanContent(t, "/app/render.py", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-008")
}

func TestXSS008_GoFprintfHTML(t *testing.T) {
	content := `fmt.Fprintf(w, "<h1>Hello %s</h1>", name)`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-008")
}

func TestXSS008_Fixture_GoXSSResponse(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/xss_response.go")
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-008")
}

func TestXSS008_Fixture_JSXSSReflected(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/xss_reflected.ts")
	result := testutil.ScanContent(t, "/app/routes/search.ts", content)
	// xss_reflected should trigger XSS-011 (reflected) patterns
	hasXSS := testutil.HasFinding(result, "GTSS-XSS-011") ||
		testutil.HasFinding(result, "GTSS-XSS-001") ||
		testutil.HasFinding(result, "GTSS-XSS-003")
	if !hasXSS {
		t.Errorf("expected at least one XSS finding in xss_reflected.ts, got %d findings: %v",
			len(result.Findings), testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-XSS-009: Missing Content-Type ---

func TestXSS009_GoHTMLNoContentType(t *testing.T) {
	content := `
package handler

func ServeHTML(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<html><body>Hello</body></html>"))
}
`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-XSS-009")
}

func TestXSS009_Safe_WithContentType(t *testing.T) {
	content := `
package handler

func ServeHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<html><body>Hello</body></html>"))
}
`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-XSS-009")
}

// --- GTSS-XSS-011: Reflected XSS ---

func TestXSS011_PythonReflected(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/xss_jinja.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	// Jinja XSS may trigger XSS-004 (unescaped template) or XSS-011
	hasXSS := testutil.HasFinding(result, "GTSS-XSS-004") || testutil.HasFinding(result, "GTSS-XSS-011")
	if !hasXSS {
		t.Errorf("expected XSS finding in xss_jinja.py, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestXSS011_PHPReflected(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/xss_reflected.php")
	result := testutil.ScanContent(t, "/app/search.php", content)
	hasXSS := testutil.HasFinding(result, "GTSS-XSS-011") || testutil.HasFinding(result, "GTSS-XSS-004")
	if !hasXSS {
		t.Errorf("expected XSS finding in xss_reflected.php, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- Safe fixture tests ---

func TestXSS_Safe_Escaped_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/xss_escaped.ts")
	result := testutil.ScanContent(t, "/app/safe.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-XSS-001")
	testutil.MustNotFindRule(t, result, "GTSS-XSS-002")
	testutil.MustNotFindRule(t, result, "GTSS-XSS-003")
}

func TestXSS_Safe_Escaped_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/safe/XssEscaped.java")
	result := testutil.ScanContent(t, "/app/Safe.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-XSS-008")
	testutil.MustNotFindRule(t, result, "GTSS-XSS-011")
}
