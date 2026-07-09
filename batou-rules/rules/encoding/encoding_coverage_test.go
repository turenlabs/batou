package encoding

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// scanDirect builds a ScanContext and invokes r.Scan directly. This is needed
// for rules that are defined but NOT registered in init() (e.g.
// IncorrectCharEncoding / BATOU-ENC-003), since testutil.ScanContent only runs
// registered rules.
func scanDirect(r rules.Rule, filePath, content string, lang rules.Language) []rules.Finding {
	ctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  content,
		Language: lang,
		IsNew:    true,
	}
	return r.Scan(ctx)
}

func hasRule(findings []rules.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findRule(findings []rules.Finding, ruleID string) (rules.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return rules.Finding{}, false
}

// ---------------------------------------------------------------------------
// BATOU-ENC-001: Double encoding (registered)
// ---------------------------------------------------------------------------

func TestENC001_TP_DoubleURLEncode(t *testing.T) {
	content := `func build(raw string) string {
	return encodeURIComponent(encodeURIComponent(raw))
}`
	result := testutil.ScanContent(t, "/app/url.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-001")

	// Verify CWE / severity metadata on the finding.
	for _, f := range result.Findings {
		if f.RuleID == "BATOU-ENC-001" {
			if f.CWEID != "CWE-174" {
				t.Fatalf("expected CWE-174, got %q", f.CWEID)
			}
			if f.Severity != rules.Medium {
				t.Fatalf("expected Medium severity, got %v", f.Severity)
			}
		}
	}
}

func TestENC001_TP_DoubleHTMLEscape(t *testing.T) {
	content := `$out = htmlspecialchars(htmlspecialchars($input));`
	result := testutil.ScanContent(t, "/app/render.php", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-001")
}

func TestENC001_Safe_SingleEncode(t *testing.T) {
	content := `url := encodeURIComponent(raw)
out := htmlspecialchars(input)`
	result := testutil.ScanContent(t, "/app/url.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-001")
}

func TestENC001_Safe_Comment(t *testing.T) {
	// A double-encode inside a comment must be skipped by isComment.
	content := `// out = htmlspecialchars(htmlspecialchars(input))
x := 1`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-001")
}

// ---------------------------------------------------------------------------
// BATOU-ENC-002: Missing output encoding (registered)
// ---------------------------------------------------------------------------

func TestENC002_TP_HTMLConcat(t *testing.T) {
	// Vulnerable: HTML string concatenated with a variable, no escape nearby.
	content := `func render(userName string) string {
	body = "<div>" + userName
	return body
}`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-002")

	f, ok := findRule(result.Findings, "BATOU-ENC-002")
	if !ok {
		t.Fatal("expected BATOU-ENC-002 finding")
	}
	if f.CWEID != "CWE-79" {
		t.Fatalf("expected CWE-79, got %q", f.CWEID)
	}
	if f.Severity != rules.High {
		t.Fatalf("expected High severity, got %v", f.Severity)
	}
}

func TestENC002_TP_FStringFormat(t *testing.T) {
	content := `def render(user_name):
    body = f"<div>{user_name}</div>"
    return body`
	result := testutil.ScanContent(t, "/app/render.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-002")
}

func TestENC002_Safe_EscapeSameLine(t *testing.T) {
	// escapeHtml on the same line trips reEscapeFuncNearby -> not flagged.
	content := `body = "<div>" + escapeHtml(userName)`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-002")
}

func TestENC002_Safe_EscapeNearbyLine(t *testing.T) {
	// Escape function within the 3-line window suppresses the finding.
	content := `safe = sanitize(userName)
body = "<div>" + safe
return body`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-002")
}

// ---------------------------------------------------------------------------
// BATOU-ENC-003: Incorrect character encoding (UNREGISTERED -> direct Scan)
// ---------------------------------------------------------------------------

func TestENC003_NotRegistered(t *testing.T) {
	// Sanity: the rule is intentionally NOT registered, so ScanContent never
	// emits it even on clearly matching content.
	content := `<meta charset="iso-8859-1">`
	result := testutil.ScanContent(t, "/app/page.html", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-003")
}

func TestENC003_TP_ContentTypeBadEncoding(t *testing.T) {
	r := &IncorrectCharEncoding{}
	content := `response.headers["Content-Type"] = "text/html; charset=iso-8859-1"`
	findings := scanDirect(r, "/app/views.py", content, rules.LangPython)
	if !hasRule(findings, "BATOU-ENC-003") {
		t.Fatalf("expected BATOU-ENC-003, got %v findings", len(findings))
	}
	f, _ := findRule(findings, "BATOU-ENC-003")
	if f.CWEID != "CWE-838" {
		t.Fatalf("expected CWE-838, got %q", f.CWEID)
	}
	if f.Severity != rules.Medium {
		t.Fatalf("expected Medium severity, got %v", f.Severity)
	}
}

func TestENC003_TP_CharsetHeader(t *testing.T) {
	r := &IncorrectCharEncoding{}
	content := `res.setHeader("Content-Type", "text/html; charset=shift_jis")`
	findings := scanDirect(r, "/app/server.js", content, rules.LangJavaScript)
	if !hasRule(findings, "BATOU-ENC-003") {
		t.Fatalf("expected BATOU-ENC-003 (charset header), got %d findings", len(findings))
	}
}

func TestENC003_TP_MetaCharset(t *testing.T) {
	r := &IncorrectCharEncoding{}
	// reCharsetMeta matches ANY meta charset declaration (including utf-8).
	content := `<meta charset="windows-1252">`
	findings := scanDirect(r, "/app/page.html", content, rules.LangAny)
	if !hasRule(findings, "BATOU-ENC-003") {
		t.Fatalf("expected BATOU-ENC-003 (meta charset), got %d findings", len(findings))
	}
}

func TestENC003_Safe_Comment(t *testing.T) {
	r := &IncorrectCharEncoding{}
	content := `<!-- <meta charset="iso-8859-1"> -->`
	findings := scanDirect(r, "/app/page.html", content, rules.LangAny)
	if hasRule(findings, "BATOU-ENC-003") {
		t.Fatal("did not expect BATOU-ENC-003 inside a comment")
	}
}

func TestENC003_Safe_NoCharset(t *testing.T) {
	r := &IncorrectCharEncoding{}
	content := `const x = 1
const y = "hello"`
	findings := scanDirect(r, "/app/app.js", content, rules.LangJavaScript)
	if hasRule(findings, "BATOU-ENC-003") {
		t.Fatal("did not expect BATOU-ENC-003 on benign content")
	}
}

// ---------------------------------------------------------------------------
// BATOU-ENC-004: URL encoding bypass (registered)
// ---------------------------------------------------------------------------

func TestENC004_TP_PercentEncodedCheck(t *testing.T) {
	content := `if path.includes("%2e%2e") {
	reject()
}`
	result := testutil.ScanContent(t, "/app/guard.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-004")

	f, _ := findRule(result.Findings, "BATOU-ENC-004")
	if f.CWEID != "CWE-177" {
		t.Fatalf("expected CWE-177, got %q", f.CWEID)
	}
	if f.Confidence != "medium" {
		t.Fatalf("expected medium confidence for percent-encoded check, got %q", f.Confidence)
	}
}

func TestENC004_TP_SecurityCheckLowConf(t *testing.T) {
	// reSecurityCheck branch: a validate() call referencing a generic %XX
	// sequence that is NOT one of the specific reserved bytes -> low conf.
	content := `validate(input, "%41")`
	result := testutil.ScanContent(t, "/app/check.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-004")

	f, _ := findRule(result.Findings, "BATOU-ENC-004")
	if f.Confidence != "low" {
		t.Fatalf("expected low confidence for generic security-check branch, got %q", f.Confidence)
	}
}

func TestENC004_Safe_NoEncodedRef(t *testing.T) {
	content := `if path.includes("..") {
	reject()
}`
	result := testutil.ScanContent(t, "/app/guard.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-004")
}

// ---------------------------------------------------------------------------
// BATOU-ENC-005: Base64 used as encryption (registered)
// ---------------------------------------------------------------------------

func TestENC005_TP_Base64AsEncrypt(t *testing.T) {
	content := `encrypted = base64.b64encode(sensitive_data)`
	result := testutil.ScanContent(t, "/app/crypto.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-005")

	f, _ := findRule(result.Findings, "BATOU-ENC-005")
	if f.CWEID != "CWE-326" {
		t.Fatalf("expected CWE-326, got %q", f.CWEID)
	}
}

func TestENC005_TP_Base64FuncOnSecret(t *testing.T) {
	content := `stored = base64_encode($password);`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-005")
}

func TestENC005_Safe_TransportEncoding(t *testing.T) {
	// Legitimate transport encoding: no crypto verb, no sensitive keyword.
	content := `encoded = base64.b64encode(image_bytes)`
	result := testutil.ScanContent(t, "/app/upload.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-005")
}

// ---------------------------------------------------------------------------
// BATOU-ENC-006: Unicode normalization bypass (registered)
// ---------------------------------------------------------------------------

func TestENC006_TP_Homoglyph(t *testing.T) {
	// Fullwidth '<' (U+FF1C) inside a file that has a security check.
	content := "func check(s string) bool {\n\tif strings.Contains(s, \"＜script＞\") {\n\t\treturn false\n\t}\n\treturn true\n}"
	result := testutil.ScanContent(t, "/app/filter.go", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-006")

	f, _ := findRule(result.Findings, "BATOU-ENC-006")
	if f.CWEID != "CWE-176" {
		t.Fatalf("expected CWE-176, got %q", f.CWEID)
	}
}

func TestENC006_TP_UnicodeCheckNoNorm(t *testing.T) {
	// Branch 2: security check referencing "unicode", file mentions "request",
	// no normalization call anywhere -> flagged.
	content := `def handler(request):
    blocked = load_blocklist()
    if input_unicode == blocked:
        deny()`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-006")
}

func TestENC006_Safe_NoSecurityCheck(t *testing.T) {
	// No security-check tokens at all -> early return nil (covers the guard).
	content := `x := 1
y := 2
total := x + y`
	result := testutil.ScanContent(t, "/app/math.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-006")
}

func TestENC006_Safe_NormalizationPresent(t *testing.T) {
	// Has a security check + "unicode" + "request" BUT normalize() present,
	// so the branch-2 finding is suppressed (hasNormalization == true).
	content := `def handler(request):
    norm = unicodedata.normalize("NFKC", input_unicode)
    if norm == blocked:
        deny()`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-006")
}

// ---------------------------------------------------------------------------
// BATOU-ENC-008: Null byte injection (registered)
// ---------------------------------------------------------------------------

func TestENC008_TP_NullByteInPath(t *testing.T) {
	content := `data = file_get_contents($upload . "%00.jpg");`
	result := testutil.ScanContent(t, "/app/files.php", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-008")

	f, _ := findRule(result.Findings, "BATOU-ENC-008")
	if f.CWEID != "CWE-626" {
		t.Fatalf("expected CWE-626, got %q", f.CWEID)
	}
	if f.Confidence != "high" {
		t.Fatalf("expected high confidence for null-byte-in-path, got %q", f.Confidence)
	}
}

func TestENC008_TP_NullByteInCheck(t *testing.T) {
	content := `if filename.endsWith(".jpg%00") { allow() }`
	result := testutil.ScanContent(t, "/app/upload.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-008")
}

func TestENC008_TP_NullByteInInput(t *testing.T) {
	content := `name = request.GET.get("file") + "%00"`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-008")
}

func TestENC008_TP_GenericNullByteWithFileContext(t *testing.T) {
	// reNullByteParam branch: a literal \x00 in a line that also mentions
	// "path"/"file" -> medium confidence.
	content := `filepath = userInput + "\x00"`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-008")

	f, _ := findRule(result.Findings, "BATOU-ENC-008")
	if f.Confidence != "medium" {
		t.Fatalf("expected medium confidence for generic null-byte+file-context, got %q", f.Confidence)
	}
}

func TestENC008_Safe_NullByteNoSecurityContext(t *testing.T) {
	// Generic null byte with NO file/path/include/open/read keyword -> not flagged.
	content := `terminator = "\x00"`
	result := testutil.ScanContent(t, "/app/proto.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-008")
}

// ---------------------------------------------------------------------------
// Helpers: truncate, isComment, nearbyLines
// ---------------------------------------------------------------------------

func TestHelper_Truncate(t *testing.T) {
	if got := truncate("short", 100); got != "short" {
		t.Fatalf("truncate should not change short strings, got %q", got)
	}
	long := strings.Repeat("a", 130)
	got := truncate(long, 120)
	if len(got) != 123 { // 120 chars + "..."
		t.Fatalf("expected truncated length 123, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected trailing ellipsis, got %q", got)
	}
}

func TestHelper_IsComment(t *testing.T) {
	cases := map[string]bool{
		"// slash":      true,
		"# hash":        true,
		"* star":        true,
		"/* block":      true,
		"<!-- html":     true,
		"code = 1":      false,
		"  // indented": false, // isComment does not trim; caller trims first
	}
	for line, want := range cases {
		if got := isComment(line); got != want {
			t.Fatalf("isComment(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestHelper_NearbyLines(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}

	// Window clamps at the start.
	if got := nearbyLines(lines, 0, 2); got != "a\nb\nc" {
		t.Fatalf("start-clamped window = %q", got)
	}
	// Window clamps at the end.
	if got := nearbyLines(lines, 4, 2); got != "c\nd\ne" {
		t.Fatalf("end-clamped window = %q", got)
	}
	// Centered window.
	if got := nearbyLines(lines, 2, 1); got != "b\nc\nd" {
		t.Fatalf("centered window = %q", got)
	}
}
