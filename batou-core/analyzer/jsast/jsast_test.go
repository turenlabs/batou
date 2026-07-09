package jsast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"testing"
)

func scanJS(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangJavaScript)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.js",
		Content:  code,
		Language: rules.LangJavaScript,
		Tree:     tree,
	}
	a := &JSASTAnalyzer{}
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

func TestEval(t *testing.T) {
	code := `
function handler(input) {
    eval(input);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-001")
	if f == nil {
		t.Error("expected eval finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `eval("1 + 2");`
	findings := scanJS(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JSAST-001" {
			t.Errorf("should not flag eval with literal: %s", f.Title)
		}
	}
}

func TestInnerHTML(t *testing.T) {
	code := `
function handler(input) {
    element.innerHTML = input;
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-002")
	if f == nil {
		t.Error("expected innerHTML XSS finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestInnerHTMLLiteralSafe(t *testing.T) {
	code := `element.innerHTML = "<p>Hello</p>";`
	findings := scanJS(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JSAST-002" {
			t.Errorf("should not flag innerHTML with literal: %s", f.Title)
		}
	}
}

func TestDocumentWrite(t *testing.T) {
	code := `
function handler(input) {
    document.write(input);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-003")
	if f == nil {
		t.Error("expected document.write XSS finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestChildProcessExec(t *testing.T) {
	code := `
var exec = require('child_process').exec;
function handler(cmd) {
    require('child_process').exec(cmd);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-004")
	if f == nil {
		t.Error("expected child_process.exec finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestNewFunction(t *testing.T) {
	code := `
function handler(code) {
    new Function(code);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-005")
	if f == nil {
		t.Error("expected new Function finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestNewFunctionLiteralSafe(t *testing.T) {
	code := `new Function("return 42");`
	findings := scanJS(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JSAST-005" {
			t.Errorf("should not flag new Function with literal: %s", f.Title)
		}
	}
}

func TestSQLTemplateLiteral(t *testing.T) {
	code := "function handler(input) {\n" +
		"    var query = `SELECT * FROM users WHERE name = '${input}'`;\n" +
		"}\n"
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-006")
	if f == nil {
		t.Error("expected SQL template literal injection finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSQLStringConcat(t *testing.T) {
	code := `
function handler(input) {
    var query = "SELECT * FROM users WHERE name = '" + input + "'";
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-006")
	if f == nil {
		t.Error("expected SQL string concat injection finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

// --- BATOU-JSAST-006: SQL concat / template-literal — FP gates (E6-T5) ---

// requireCritical asserts a JSAST-006 finding exists and is CRITICAL.
func requireSQLConcatFinding(t *testing.T, code string) {
	t.Helper()
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-006")
	if f == nil {
		t.Fatalf("expected BATOU-JSAST-006 finding for %q; got %v", code, ruleIDsOf(findings))
	}
	if f.Severity != rules.Critical {
		t.Fatalf("expected CRITICAL severity, got %v", f.Severity)
	}
}

func requireNoSQLConcatFinding(t *testing.T, code string) {
	t.Helper()
	findings := scanJS(code)
	if f := findByRule(findings, "BATOU-JSAST-006"); f != nil {
		t.Fatalf("did not expect BATOU-JSAST-006 for %q; got finding %q at line %d", code, f.Title, f.LineNumber)
	}
}

func ruleIDsOf(fs []rules.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

// The owncloud/web FP: numeric addition whose identifier *contains* a SQL
// keyword as a substring (`latestSelectedResourceIndex` -> "Selected").
func TestSQLConcat_NumericAddition_NoFP(t *testing.T) {
	for _, code := range []string{
		"function f() { var x = latestSelectedResourceIndex + step; }",
		"function f() { const next = offset + limit; }",
		"function f() { let n = currentInsertedRows + 1; }",
		"function f() { var i = updatedCount + deletedCount; }",
		"function f() { const idx = i + 1 + j; }",
	} {
		requireNoSQLConcatFinding(t, code)
	}
}

// Concatenation that builds an English log/error message containing a bare
// SQL verb ("Update failed", "Delete this", "/select-all/") must not fire —
// it has no SQL *shape* (no FROM/SET/WHERE/INTO pairing).
func TestSQLConcat_LogMessage_NoFP(t *testing.T) {
	for _, code := range []string{
		`function f() { var msg = "Update failed for resource " + id + " - retrying"; }`,
		`function f() { var msg = "Delete this item? " + name; }`,
		`function f() { var route = "/select-all/" + page; }`,
		`function f() { var label = "Where did " + user + " go?"; }`,
	} {
		requireNoSQLConcatFinding(t, code)
	}
}

// Template literal that is not SQL (DOM-selector style, log message) — even
// if a SQL verb substring appears it lacks the shape.
func TestSQLTemplate_NotSQL_NoFP(t *testing.T) {
	for _, code := range []string{
		"function f() { var sel = `.foo-${id}`; }",
		"function f() { var sel = `[data-id='${id}']`; }",
		"function f() { var msg = `done ${count} records`; }",
		"function f() { var path = `${base}/select-from-here/${page}`; }",
	} {
		requireNoSQLConcatFinding(t, code)
	}
}

// Real SQL injection via concat — must still fire CRITICAL.
func TestSQLConcat_RealSQLi_Fires(t *testing.T) {
	requireSQLConcatFinding(t,
		`function f(input) { var q = "SELECT * FROM users WHERE name = '" + input + "'"; }`)
	requireSQLConcatFinding(t,
		`function f(id) { var q = "DELETE FROM sessions WHERE id = " + id; }`)
	requireSQLConcatFinding(t,
		`function f(v) { var q = "INSERT INTO logs (msg) VALUES ('" + v + "')"; }`)
	requireSQLConcatFinding(t,
		`function f(name, id) { var q = "UPDATE users SET name = '" + name + "' WHERE id = " + id; }`)
}

// Real SQL injection via template literal — must still fire CRITICAL.
func TestSQLTemplate_RealSQLi_Fires(t *testing.T) {
	requireSQLConcatFinding(t,
		"function f(input) { var q = `SELECT * FROM users WHERE name = '${input}'`; }")
	requireSQLConcatFinding(t,
		"function f(id) { var q = `DELETE FROM sessions WHERE token = '${id}'`; }")
	requireSQLConcatFinding(t,
		"function f(col) { var q = `SELECT id FROM t ORDER BY ${col}`; }")
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.js",
		Content:  "eval(x)",
		Language: rules.LangJavaScript,
		Tree:     nil,
	}
	a := &JSASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "eval(x)",
		Language: rules.LangPython,
	}
	a := &JSASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestTypeScript(t *testing.T) {
	code := `
function handler(input: string) {
    eval(input);
}
`
	tree := ast.Parse([]byte(code), rules.LangTypeScript)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.ts",
		Content:  code,
		Language: rules.LangTypeScript,
		Tree:     tree,
	}
	a := &JSASTAnalyzer{}
	findings := a.Scan(ctx)
	f := findByRule(findings, "BATOU-JSAST-001")
	if f == nil {
		t.Error("expected eval finding for TypeScript")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
// comment
function handler(input) {
    eval(input);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "BATOU-JSAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}

// JSAST-002 false-positive suppression — innerHTML assignments where the
// RHS is a safe-shaped expression should not fire.
func TestInnerHTMLSafeExpressions(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"svg_helper", `el.innerHTML = svg('octicon-copy');`},
		{"html_tagged_template_no_subst", "el.innerHTML = html`<div></div>`;"},
		{"html_tagged_template_with_subst", "el.innerHTML = html`<div>${x}</div>`;"},
		{"plain_template_string_no_subst", "el.innerHTML = `<div></div>`;"},
		{"sanitize_call", `el.innerHTML = DOMPurify.sanitize(input);`},
		{"sanitize_bare", `el.innerHTML = sanitize(input);`},
		{"string_literal", `el.innerHTML = "<p>Hello</p>";`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanJS(tc.code)
			for _, f := range findings {
				if f.RuleID == "BATOU-JSAST-002" {
					t.Errorf("safe innerHTML expression flagged: %s — %s", f.Title, f.MatchedText)
				}
			}
		})
	}
}

// JSAST-002 should still fire when the RHS is a user-derived variable or
// a template string with a plain substitution (no sanitization in scope).
func TestInnerHTMLUnsafeExpressions(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"bare_variable", `function f(input){ el.innerHTML = input; }`},
		{"concatenation", `function f(input){ el.innerHTML = "<p>" + input + "</p>"; }`},
		{"plain_template_with_subst", "function f(input){ el.innerHTML = `<p>${input}</p>`; }"},
		{"member_access", `function f(req){ el.innerHTML = req.body.html; }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanJS(tc.code)
			if findByRule(findings, "BATOU-JSAST-002") == nil {
				t.Errorf("expected JSAST-002 finding, got none")
			}
		})
	}
}

// JSAST-002 real-world FP shapes — these are the *exact* innerHTML assignments
// that fired (39 of them) on Discourse + Nextcloud during a smoke scan despite
// having a constant / developer-authored / numeric RHS that cannot carry
// attacker HTML. They must now stay CLEAN. The companion test
// TestInnerHTML_RealWorld_TPStillFires proves the tightening did not disable
// the rule for genuinely tainted RHS shapes.
func TestInnerHTML_RealWorldFP_NoFire(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		// Numeric expression — `parseInt(...) + 1` is a Number, never HTML.
		// (Discourse lib/click-track.js: `badge.innerHTML = parseInt(html,10)+1`)
		{"numeric_parseint_add", `function f(html){ badge.innerHTML = parseInt(html, 10) + 1; }`},
		// Typed-icon builder call — returns a fixed SVG snippet keyed by a
		// constant name. (Discourse lib/codeblock-buttons.js)
		{"iconHTML_call", `overlay.innerHTML = iconHTML("play");`},
		// i18n localization — visible text is a developer-authored template
		// selected by a constant message id. (Discourse lib/codeblock-buttons.js)
		{"i18n_call", `button.innerHTML = i18n("copy_codeblock.copied");`},
		// Nextcloud / i18next translate alias.
		// (Nextcloud apps/files_external/.../inlineStorageCheckAction.ts)
		{"t_translate_call", `span.innerHTML = t('files_external', 'Checking storage');`},
		// Concatenation of only safe builders + literals.
		// (Discourse instance-initializers/video-placeholder.js)
		{"concat_of_safe_builders", `notice.innerHTML = iconHTML("triangle-exclamation") + " " + i18n("invalid_video_url");`},
		// Template literal interpolating ONLY safe-builder calls.
		// (Discourse instance-initializers/animated-images-pause-on-click.js)
		{"template_of_safe_builders", "overlay.innerHTML = `${iconHTML(\"pause\")}${iconHTML(\"play\")}`;"},
		// Template interpolating only an i18n call.
		// (Discourse instance-initializers/post-decorations.js, simplified)
		{"template_of_i18n", "btn.innerHTML = `<span>${i18n(props.label)}</span>`;"},
		// Plain string literal HTML.
		{"string_literal_html", `x.innerHTML = "<p>Hello</p>";`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanJS(tc.code)
			if f := findByRule(findings, "BATOU-JSAST-002"); f != nil {
				t.Errorf("real-world safe innerHTML FP fired: line %d — %s", f.LineNumber, f.MatchedText)
			}
		})
	}
}

// JSAST-002 must STILL fire on the genuinely-dangerous innerHTML shapes that
// appeared alongside the FPs in the same repos: bare variables, member
// accesses, and templates that interpolate a plain variable (not a safe
// builder). This is the proof that the FP gate tightened, not disabled, the
// rule — the same sink with a tainted-shaped RHS keeps firing.
func TestInnerHTML_RealWorld_TPStillFires(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		// Bare variable holding prior HTML. (Discourse lib/codeblock-buttons.js:
		// `button.innerHTML = state`)
		{"bare_variable_state", `function f(state){ button.innerHTML = state; }`},
		// Cooked/rendered HTML variable. (Discourse lib/text.js: `div.innerHTML = cooked`)
		{"cooked_variable", `function f(cooked){ div.innerHTML = cooked; }`},
		// Member access onto node attrs. (Discourse onebox.js: `dom.innerHTML = node.attrs.html`)
		{"member_access_attrs", `function f(node){ dom.innerHTML = node.attrs.html; }`},
		// Template interpolating a plain variable next to a safe builder — the
		// variable substitution is unsafe so it must fire.
		// (Discourse static/prosemirror/extensions/hashtag.js:
		// `domNode.innerHTML = ` + "`${hashtagIconHTML}${tagText}`")
		{"template_with_var_subst", "function f(hashtagIconHTML, tagText){ domNode.innerHTML = `${hashtagIconHTML}${tagText}`; }"},
		// Template that mixes a bare-variable substitution with HTML — the
		// `${iconHTML}` operand is a plain identifier (not a safe-builder
		// *call*), so the template is unsafe and fires. (Discourse
		// lib/hashtag-decorator.js, full line.)
		{"template_with_bare_ident_subst", "function f(iconHTML, data){ link.innerHTML = `${iconHTML}<span>${data.text}</span>`; }"},
		// Concatenation that includes a user variable operand.
		{"concat_with_var", `function f(input){ el.innerHTML = "<p>" + input + "</p>"; }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanJS(tc.code)
			if findByRule(findings, "BATOU-JSAST-002") == nil {
				t.Errorf("expected JSAST-002 to still fire on dangerous RHS, got none for %q", tc.code)
			}
		})
	}
}
