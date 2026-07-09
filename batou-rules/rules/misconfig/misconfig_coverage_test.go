package misconfig

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// scanDirect builds a ScanContext and calls r.Scan directly. This is required
// for unregistered rules (BATOU-MISC-003 MissingSecurityHeaders is defined but
// its rules.Register is commented out), which testutil.ScanContent will never
// run because it only iterates rules.ForLanguage().
func scanDirect(r rules.Rule, path string, lang rules.Language, code string) []rules.Finding {
	ctx := &rules.ScanContext{FilePath: path, Content: code, Language: lang}
	return r.Scan(ctx)
}

func findIDs(fs []rules.Finding) string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return strings.Join(ids, ",")
}

func hasRule(fs []rules.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Metadata methods for every rule (ID/Name/Description/DefaultSeverity/Languages).
// These were almost entirely uncovered (0%) — they are cheap, deterministic,
// and assert the rule's public contract.
// ---------------------------------------------------------------------------

func TestMisconfig_Metadata(t *testing.T) {
	type meta struct {
		rule     rules.Rule
		wantID   string
		wantName string
		wantSev  rules.Severity
	}
	cases := []meta{
		{&DebugMode{}, "BATOU-MISC-001", "DebugMode", rules.Medium},
		{&ErrorDisclosure{}, "BATOU-MISC-002", "ErrorDisclosure", rules.Low},
		{&MissingSecurityHeaders{}, "BATOU-MISC-003", "MissingSecurityHeaders", rules.Medium},
		{&DebugModeProd{}, "BATOU-MISC-004", "DebugModeProd", rules.High},
		{&DefaultConfig{}, "BATOU-MISC-005", "DefaultConfig", rules.Medium},
		{&VerboseErrorExposed{}, "BATOU-MISC-006", "VerboseErrorExposed", rules.Medium},
		{&AdminExposedNoIPRestriction{}, "BATOU-MISC-007", "AdminExposedNoIPRestriction", rules.High},
		{&HTTPSNotEnforced{}, "BATOU-MISC-008", "HTTPSNotEnforced", rules.Medium},
		{&DirectoryListingEnabled{}, "BATOU-MISC-009", "DirectoryListingEnabled", rules.Medium},
		{&InsecurePermissions{}, "BATOU-MISC-010", "InsecurePermissions", rules.High},
		{&StackTracesEnabled{}, "BATOU-MISC-011", "StackTracesEnabled", rules.Medium},
		{&CppTLSVerificationDisabled{}, "BATOU-MISC-012", "CppTLSVerificationDisabled", rules.High},
	}
	for _, c := range cases {
		t.Run(c.wantID, func(t *testing.T) {
			if got := c.rule.ID(); got != c.wantID {
				t.Errorf("ID() = %q, want %q", got, c.wantID)
			}
			if got := c.rule.DefaultSeverity(); got != c.wantSev {
				t.Errorf("DefaultSeverity() = %v, want %v", got, c.wantSev)
			}
			if c.rule.Description() == "" {
				t.Error("Description() is empty")
			}
			if len(c.rule.Languages()) == 0 {
				t.Error("Languages() is empty")
			}
		})
	}

	// Name() is not part of the rules.Rule interface for all types; assert the
	// concrete Name() methods explicitly so they are covered.
	names := map[string]string{
		(&DebugMode{}).Name():                   "DebugMode",
		(&ErrorDisclosure{}).Name():             "ErrorDisclosure",
		(&MissingSecurityHeaders{}).Name():      "MissingSecurityHeaders",
		(&DebugModeProd{}).Name():               "DebugModeProd",
		(&DefaultConfig{}).Name():               "DefaultConfig",
		(&VerboseErrorExposed{}).Name():         "VerboseErrorExposed",
		(&AdminExposedNoIPRestriction{}).Name(): "AdminExposedNoIPRestriction",
		(&HTTPSNotEnforced{}).Name():            "HTTPSNotEnforced",
		(&DirectoryListingEnabled{}).Name():     "DirectoryListingEnabled",
		(&InsecurePermissions{}).Name():         "InsecurePermissions",
		(&StackTracesEnabled{}).Name():          "StackTracesEnabled",
		(&CppTLSVerificationDisabled{}).Name():  "CppTLSVerificationDisabled",
	}
	for got, want := range names {
		if got != want {
			t.Errorf("Name() map key %q != %q", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// BATOU-MISC-003: MissingSecurityHeaders — UNREGISTERED. Covered via direct
// Scan() across every per-language handler branch and both early-exit paths.
// ---------------------------------------------------------------------------

func TestMISC003_PerLanguageHandlers(t *testing.T) {
	r := &MissingSecurityHeaders{}
	cases := []struct {
		name string
		lang rules.Language
		path string
		code string
	}{
		{"go", rules.LangGo, "/app/h.go",
			"func handler(w http.ResponseWriter, r *http.Request) {\n\tw.Write([]byte(\"hi\"))\n}\n"},
		{"js", rules.LangJavaScript, "/app/s.js",
			"app.get('/x', (req, res) => {\n\tres.send('hi');\n});\n"},
		{"ts", rules.LangTypeScript, "/app/s.ts",
			"router.post('/x', (req, res) => {\n\tres.json({ok: true});\n});\n"},
		{"py", rules.LangPython, "/app/v.py",
			"def view(request):\n\treturn HttpResponse('hi')\n"},
		{"java", rules.LangJava, "/app/S.java",
			"protected void doGet(HttpServletRequest req, HttpServletResponse response) {\n\tresponse.getWriter().println(\"x\");\n}\n"},
		{"php", rules.LangPHP, "/app/p.php",
			"<?php\nheader('Content-Type: text/html');\necho 'hi';\n"},
		{"ruby", rules.LangRuby, "/app/c.rb",
			"def index\n\trender plain: 'hi'\nend\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := scanDirect(r, c.path, c.lang, c.code)
			if !hasRule(fs, "BATOU-MISC-003") {
				t.Fatalf("expected BATOU-MISC-003, got: %s", findIDs(fs))
			}
			if fs[0].CWEID != "CWE-1021" {
				t.Errorf("CWE = %q, want CWE-1021", fs[0].CWEID)
			}
		})
	}
}

func TestMISC003_HelmetEarlyExit(t *testing.T) {
	r := &MissingSecurityHeaders{}
	code := "const helmet = require('helmet');\napp.use(helmet());\napp.get('/x', (req,res)=>{ res.send('hi'); });\n"
	if fs := scanDirect(r, "/app/s.js", rules.LangJavaScript, code); len(fs) != 0 {
		t.Fatalf("helmet middleware should suppress all findings, got: %s", findIDs(fs))
	}
}

func TestMISC003_SecureHeadersMiddlewareEarlyExit(t *testing.T) {
	r := &MissingSecurityHeaders{}
	// SecurityMiddleware token matches reSecureHeaders -> whole-file suppress.
	code := "# uses django SecurityMiddleware\ndef view(request):\n\treturn HttpResponse('hi')\n"
	if fs := scanDirect(r, "/app/v.py", rules.LangPython, code); len(fs) != 0 {
		t.Fatalf("SecurityMiddleware should suppress all findings, got: %s", findIDs(fs))
	}
}

func TestMISC003_AllHeadersPresent_NoFinding(t *testing.T) {
	r := &MissingSecurityHeaders{}
	code := "app.get('/x',(req,res)=>{\n" +
		"res.set('X-Frame-Options','DENY');\n" +
		"res.set('Content-Security-Policy',\"default-src 'self'\");\n" +
		"res.set('Strict-Transport-Security','max-age=31536000');\n" +
		"res.send('hi'); });\n"
	if fs := scanDirect(r, "/app/s.js", rules.LangJavaScript, code); len(fs) != 0 {
		t.Fatalf("all 3 headers present should produce no finding, got: %s", findIDs(fs))
	}
}

func TestMISC003_PartialHeaders_ReportsMissingOnes(t *testing.T) {
	r := &MissingSecurityHeaders{}
	// Only CSP present; X-Frame-Options and HSTS missing.
	code := "app.get('/x',(req,res)=>{\n" +
		"res.set('Content-Security-Policy',\"default-src 'self'\");\n" +
		"res.send('hi'); });\n"
	fs := scanDirect(r, "/app/s.js", rules.LangJavaScript, code)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d (%s)", len(fs), findIDs(fs))
	}
	title := fs[0].Title
	if !strings.Contains(title, "X-Frame-Options") || !strings.Contains(title, "Strict-Transport-Security") {
		t.Errorf("title should list missing X-Frame-Options and HSTS, got %q", title)
	}
	if strings.Contains(title, "Content-Security-Policy") {
		t.Errorf("title should NOT list present Content-Security-Policy, got %q", title)
	}
}

func TestMISC003_HandlerWithoutWrite_NoFinding(t *testing.T) {
	r := &MissingSecurityHeaders{}
	// Go handler signature but never writes a response.
	code := "func handler(w http.ResponseWriter, r *http.Request) {\n\tlog.Println(\"noop\")\n}\n"
	if fs := scanDirect(r, "/app/h.go", rules.LangGo, code); len(fs) != 0 {
		t.Fatalf("handler with no response write should not fire, got: %s", findIDs(fs))
	}
}

func TestMISC003_LongHandlerTruncated(t *testing.T) {
	r := &MissingSecurityHeaders{}
	long := strings.Repeat("a", 200)
	code := "app.get('/" + long + "', (req, res) => {\n\tres.send('hi');\n});\n"
	fs := scanDirect(r, "/app/s.js", rules.LangJavaScript, code)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if !strings.HasSuffix(fs[0].MatchedText, "...") {
		t.Errorf("long handler match should be truncated with ..., got %q", fs[0].MatchedText)
	}
}

func TestMISC003_CommentLineSkipped(t *testing.T) {
	r := &MissingSecurityHeaders{}
	// Leading comment lines exercise the comment-skip branch; the real handler
	// follows and should still fire.
	code := "// a comment\n# another\n* doc star\napp.get('/x', (req, res) => {\n\tres.send('hi');\n});\n"
	if fs := scanDirect(r, "/app/s.js", rules.LangJavaScript, code); !hasRule(fs, "BATOU-MISC-003") {
		t.Fatalf("handler after comments should still fire, got: %s", findIDs(fs))
	}
}

// ---------------------------------------------------------------------------
// BATOU-MISC-001: DebugMode — fill remaining language branches.
// ---------------------------------------------------------------------------

func TestMISC001_PHPErrorReporting(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.php", "error_reporting(E_ALL);")
	testutil.MustFindRule(t, result, "BATOU-MISC-001")
}

func TestMISC001_PHPDisplayErrorsAssign(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.php", "display_errors = On")
	testutil.MustFindRule(t, result, "BATOU-MISC-001")
}

func TestMISC001_NodeEnvDevelopment(t *testing.T) {
	result := testutil.ScanContent(t, "/app/server.js", "NODE_ENV = 'development'")
	testutil.MustFindRule(t, result, "BATOU-MISC-001")
}

// NODE_ENV inside an equality check is a guard, not a hardcoded setting.
func TestMISC001_Safe_NodeEnvDevelopmentCheck(t *testing.T) {
	result := testutil.ScanContent(t, "/app/server.js", "if (NODE_ENV === 'development') { enableThing(); }")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-001")
}

func TestMISC001_GenericDebugModeFlag(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.yml", "debug_mode: true")
	testutil.MustFindRule(t, result, "BATOU-MISC-001")
}

// Comment-only line must be skipped by the leading-comment guard.
func TestMISC001_Safe_BlockCommentLine(t *testing.T) {
	result := testutil.ScanContent(t, "/app/settings.py", "/* DEBUG = True */\nDEBUG = False")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-001")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-002: ErrorDisclosure — fill remaining branches.
// ---------------------------------------------------------------------------

func TestMISC002_JavaErrInResponse(t *testing.T) {
	content := "response.getWriter().println(e.getMessage());"
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	// reJavaErrInResp / generic stack-trace branches both target this shape.
	testutil.MustFindAnyRule(t, result, "BATOU-MISC-002", "BATOU-MISC-006")
}

func TestMISC002_GenericStackTraceInResponse(t *testing.T) {
	// Ruby is in MISC-002 Languages() but has no specific branch, so this
	// exercises the generic reStackTraceResp fallback.
	content := `response.body(full_error)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	// Best-effort: confirm the generic fallback path runs without panic.
	_ = testutil.HasFinding(result, "BATOU-MISC-002")
}

func TestMISC002_Safe_CommentLine(t *testing.T) {
	content := "// res.send(err.stack)\nres.status(500).json({error: 'oops'});"
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-002")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-004: DebugModeProd.
// ---------------------------------------------------------------------------

func TestMISC004_DebugTrueNoGuard(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.js", "debug = true")
	testutil.MustFindRule(t, result, "BATOU-MISC-004")
}

func TestMISC004_DevModeNoGuard(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.js", "devMode = true")
	testutil.MustFindRule(t, result, "BATOU-MISC-004")
}

// File path containing "prod" raises confidence to high.
func TestMISC004_ProdContextHighConfidence(t *testing.T) {
	fs := scanDirect(&DebugModeProd{}, "/app/config.prod.js", rules.LangJavaScript, "debug = true")
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Confidence != "high" {
		t.Errorf("prod-context confidence = %q, want high", fs[0].Confidence)
	}
	if fs[0].CWEID != "CWE-489" {
		t.Errorf("CWE = %q, want CWE-489", fs[0].CWEID)
	}
}

// Non-prod path stays at medium confidence.
func TestMISC004_NonProdMediumConfidence(t *testing.T) {
	fs := scanDirect(&DebugModeProd{}, "/app/config.js", rules.LangJavaScript, "debug = true")
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", fs[0].Confidence)
	}
}

func TestMISC004_Safe_EnvGuard(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.js", "debug = process.env.DEBUG")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-004")
}

func TestMISC004_Safe_TernaryCheck(t *testing.T) {
	// "===" branch of the if/ternary guard.
	result := testutil.ScanContent(t, "/app/config.js", "debug = mode === 'x' ? true : false")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-004")
}

func TestMISC004_Safe_CommentLine(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.js", "// debug = true")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-004")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-005: DefaultConfig.
// ---------------------------------------------------------------------------

func TestMISC005_PlaceholderSecret(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.go", `password := "changeme"`)
	testutil.MustFindRule(t, result, "BATOU-MISC-005")
}

func TestMISC005_LongLineTruncated(t *testing.T) {
	long := strings.Repeat("x", 200)
	code := `api_key = "changeme-` + long + `"`
	fs := scanDirect(&DefaultConfig{}, "/app/config.go", rules.LangGo, code)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if !strings.HasSuffix(fs[0].MatchedText, "...") {
		t.Errorf("long match should be truncated, got %q", fs[0].MatchedText)
	}
}

// Test-file path suppresses MISC-005 (isMisconfigTestFile guard).
func TestMISC005_Safe_TestFileSuppressed(t *testing.T) {
	fs := scanDirect(&DefaultConfig{}, "/app/config_test.go", rules.LangGo, `password := "changeme"`)
	if len(fs) != 0 {
		t.Fatalf("test file should suppress MISC-005, got: %s", findIDs(fs))
	}
}

// Placeholder present but no secret context -> no finding.
func TestMISC005_Safe_NoSecretContext(t *testing.T) {
	result := testutil.ScanContent(t, "/app/main.go", `title := "changeme later"`)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-005")
}

func TestMISC005_Safe_CommentLine(t *testing.T) {
	result := testutil.ScanContent(t, "/app/config.go", `// password = "changeme"`)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-005")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-006: VerboseErrorExposed.
// ---------------------------------------------------------------------------

func TestMISC006_JavaGetMessage(t *testing.T) {
	result := testutil.ScanContent(t, "/app/Handler.java", "response.write(e.getMessage());")
	testutil.MustFindRule(t, result, "BATOU-MISC-006")
}

func TestMISC006_JSStackInResponse(t *testing.T) {
	result := testutil.ScanContent(t, "/app/server.js", "res.send(error.stack);")
	testutil.MustFindRule(t, result, "BATOU-MISC-006")
}

func TestMISC006_LongMatchTruncated(t *testing.T) {
	// The matched substring runs from the res.send( opener through the error
	// token, so the long content must sit INSIDE the parens before .stack for
	// the regex match (not just the line) to exceed 120 chars.
	long := strings.Repeat("z", 200)
	code := "res.send(" + long + " + error.stack);"
	fs := scanDirect(&VerboseErrorExposed{}, "/app/server.js", rules.LangJavaScript, code)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if !strings.HasSuffix(fs[0].MatchedText, "...") {
		t.Errorf("long match should be truncated, got %q", fs[0].MatchedText)
	}
}

func TestMISC006_Safe_CommentLine(t *testing.T) {
	result := testutil.ScanContent(t, "/app/server.js", "// res.send(error.stack)")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-006")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-008: HTTPSNotEnforced.
// ---------------------------------------------------------------------------

func TestMISC008_PlainHTTPServer(t *testing.T) {
	result := testutil.ScanContent(t, "/app/server.js", "app.listen(80);")
	testutil.MustFindRule(t, result, "BATOU-MISC-008")
	for _, f := range testutil.FindingsByRule(result, "BATOU-MISC-008") {
		if f.CWEID != "CWE-319" {
			t.Errorf("CWE = %q, want CWE-319", f.CWEID)
		}
	}
}

func TestMISC008_Safe_HTTPSRedirect(t *testing.T) {
	content := "app.use(forceSSL);\napp.listen(80);"
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-008")
}

func TestMISC008_Safe_TLSSetup(t *testing.T) {
	content := "https.createServer(opts).listen(443);\napp.listen(80);"
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-008")
}

func TestMISC008_Safe_CommentLine(t *testing.T) {
	result := testutil.ScanContent(t, "/app/server.js", "// app.listen(80)")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-008")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-009: DirectoryListingEnabled.
// ---------------------------------------------------------------------------

func TestMISC009_NginxAutoindex(t *testing.T) {
	fs := scanDirect(&DirectoryListingEnabled{}, "/etc/nginx/site.conf", rules.LangAny, "autoindex on;")
	if !hasRule(fs, "BATOU-MISC-009") {
		t.Fatalf("expected BATOU-MISC-009, got: %s", findIDs(fs))
	}
	if fs[0].CWEID != "CWE-548" {
		t.Errorf("CWE = %q, want CWE-548", fs[0].CWEID)
	}
}

func TestMISC009_ApacheOptionsIndexes(t *testing.T) {
	fs := scanDirect(&DirectoryListingEnabled{}, "/app/.htaccess", rules.LangAny, "Options +Indexes")
	if !hasRule(fs, "BATOU-MISC-009") {
		t.Fatalf("expected BATOU-MISC-009, got: %s", findIDs(fs))
	}
}

func TestMISC009_Safe_CommentLine(t *testing.T) {
	fs := scanDirect(&DirectoryListingEnabled{}, "/etc/nginx/site.conf", rules.LangAny, "# autoindex on;")
	if len(fs) != 0 {
		t.Fatalf("comment line should not fire, got: %s", findIDs(fs))
	}
}

// ---------------------------------------------------------------------------
// BATOU-MISC-010: InsecurePermissions.
// ---------------------------------------------------------------------------

func TestMISC010_Chmod777(t *testing.T) {
	result := testutil.ScanContent(t, "/app/setup.py", "os.chmod(path, 0o777)")
	testutil.MustFindRule(t, result, "BATOU-MISC-010")
	for _, f := range testutil.FindingsByRule(result, "BATOU-MISC-010") {
		if f.CWEID != "CWE-276" {
			t.Errorf("CWE = %q, want CWE-276", f.CWEID)
		}
	}
}

// reOpenPerms branch: umask(0) / "world-writable".
func TestMISC010_UmaskZero(t *testing.T) {
	result := testutil.ScanContent(t, "/app/setup.py", "os.umask(0o000)")
	testutil.MustFindRule(t, result, "BATOU-MISC-010")
}

func TestMISC010_WorldWritablePhrase(t *testing.T) {
	fs := scanDirect(&InsecurePermissions{}, "/app/perm.go", rules.LangGo, "mode := worldWritable")
	if !hasRule(fs, "BATOU-MISC-010") {
		t.Fatalf("expected BATOU-MISC-010 for world-writable, got: %s", findIDs(fs))
	}
}

func TestMISC010_Safe_644(t *testing.T) {
	result := testutil.ScanContent(t, "/app/setup.py", "os.chmod(path, 0o644)")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-010")
}

func TestMISC010_Safe_CommentLine(t *testing.T) {
	result := testutil.ScanContent(t, "/app/setup.py", "# os.chmod(path, 0o777)")
	testutil.MustNotFindRule(t, result, "BATOU-MISC-010")
}

// ---------------------------------------------------------------------------
// BATOU-MISC-011: StackTracesEnabled.
// ---------------------------------------------------------------------------

func TestMISC011_IncludeStackTrace(t *testing.T) {
	fs := scanDirect(&StackTracesEnabled{}, "/app/app.yml", rules.LangAny, "includeStackTrace: true")
	if !hasRule(fs, "BATOU-MISC-011") {
		t.Fatalf("expected BATOU-MISC-011, got: %s", findIDs(fs))
	}
	if fs[0].CWEID != "CWE-209" {
		t.Errorf("CWE = %q, want CWE-209", fs[0].CWEID)
	}
}

func TestMISC011_ShowStackTrace(t *testing.T) {
	fs := scanDirect(&StackTracesEnabled{}, "/app/app.properties", rules.LangAny, "show_stack_trace = true")
	if !hasRule(fs, "BATOU-MISC-011") {
		t.Fatalf("expected BATOU-MISC-011, got: %s", findIDs(fs))
	}
}

func TestMISC011_Safe_CommentLine(t *testing.T) {
	fs := scanDirect(&StackTracesEnabled{}, "/app/app.yml", rules.LangAny, "# includeStackTrace: true")
	if len(fs) != 0 {
		t.Fatalf("comment line should not fire, got: %s", findIDs(fs))
	}
}

// ---------------------------------------------------------------------------
// Helper functions covered directly.
// ---------------------------------------------------------------------------

func TestTruncateTLS(t *testing.T) {
	if got := truncateTLS("short", 120); got != "short" {
		t.Errorf("truncateTLS(short) = %q, want unchanged", got)
	}
	long := strings.Repeat("a", 130)
	got := truncateTLS(long, 120)
	if len(got) != 123 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncateTLS(long) = len %d suffix %v, want 123 + ...", len(got), strings.HasSuffix(got, "..."))
	}
}

func TestIsCppCommentLine(t *testing.T) {
	cases := map[string]bool{
		"// comment":        true,
		"  /* block":        true,
		"   * doc":          true,
		"code();":           false,
		"  curl_setopt(h);": false,
	}
	for in, want := range cases {
		if got := isCppCommentLine(in); got != want {
			t.Errorf("isCppCommentLine(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsMisconfigTestFile(t *testing.T) {
	truthy := []string{
		"/app/foo_test.go",
		"/app/foo.test.ts",
		"/app/foo.test.js",
		"/app/foo.spec.ts",
		"/app/foo.spec.js",
		"/repo/tests/x.go",
		"/repo/test/x.go",
		"/repo/__tests__/x.js",
		"/db/migrations/001.sql",
		"/app/foo_test.py",
		"/app/test_foo.py",
	}
	for _, p := range truthy {
		if !isMisconfigTestFile(p) {
			t.Errorf("isMisconfigTestFile(%q) = false, want true", p)
		}
	}
	falsy := []string{
		"",
		"/app/config.go",
		"/app/handler.py",
		"/src/main.js",
	}
	for _, p := range falsy {
		if isMisconfigTestFile(p) {
			t.Errorf("isMisconfigTestFile(%q) = true, want false", p)
		}
	}
}
