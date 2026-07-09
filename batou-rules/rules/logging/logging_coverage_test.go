package logging

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// scanDirect builds a ScanContext and calls r.Scan directly. Used for rules
// that are not wired into init()'s rules.Register (e.g. MissingAuditLogging),
// which testutil.ScanContent would never run.
func scanDirect(r rules.Rule, lang rules.Language, path, content string) []rules.Finding {
	ctx := &rules.ScanContext{
		FilePath: path,
		Content:  content,
		Language: lang,
		IsNew:    true,
	}
	return r.Scan(ctx)
}

func hasRule(findings []rules.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Unexported helpers: truncate / isCommentLine / logArgIsOnlyStringMessage
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		maxLen int
		want   string
	}{
		{"short_unchanged", "hello", 10, "hello"},
		{"trimmed_then_short", "   hi   ", 10, "hi"},
		{"exactly_max", "abcde", 5, "abcde"},
		{"over_max_truncated", "abcdefghij", 5, "abcde..."},
		{"trim_before_length_check", "  abcdefghij  ", 5, "abcde..."},
		{"empty", "", 4, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.in, tc.maxLen); got != tc.want {
				t.Fatalf("truncate(%q, %d) = %q, want %q", tc.in, tc.maxLen, got, tc.want)
			}
		})
	}
}

func TestIsCommentLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"// a comment", true},
		{"  // indented comment", true},
		{"# python comment", true},
		{"-- sql comment", true},
		{"; ini comment", true},
		{"% latex comment", true},
		{"/* block start", true},
		{"* javadoc continuation", true},
		{`logger.info("real code")`, false},
		{"", false},
		{"x := 1 // trailing comment is NOT a comment line", false},
	}
	for _, tc := range cases {
		if got := isCommentLine(tc.line); got != tc.want {
			t.Errorf("isCommentLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestLogArgIsOnlyStringMessage(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		// Single static literal messages → true (FP gate engages).
		{"single_double_quote", `logger.info("just a message")`, true},
		{"single_single_quote", `console.debug('a static message')`, true},
		{"backtick_no_interp", "logger.info(`a static template`)", true},
		{"escaped_quote_inside", `logger.info("he said \"hi\" there")`, true},
		// Not a single message → false (rule still fires).
		{"no_log_call", `foo := bar + baz`, false},
		{"interpolation_backtick", "logger.info(`pwd=${password}`)", false},
		{"concatenation", `logger.info("token: " + accessToken)`, false},
		{"multiple_args", `log.Printf("secret %s", apiSecret)`, false},
		{"empty_args", `logger.info()`, false},
		{"unbalanced_parens_multiline", `logger.info("start of a call that`, false},
		{"not_a_quoted_literal", `logger.info(variableName)`, false},
		// Text after the matched ")" is not inspected — the call's argument
		// list is a single literal, so the gate still reports true.
		{"single_literal_trailing_concat_ignored", `logger.info("a") + "b"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := logArgIsOnlyStringMessage(tc.line); got != tc.want {
				t.Fatalf("logArgIsOnlyStringMessage(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-001 additional language/branch coverage
// ---------------------------------------------------------------------------

func TestLOG001_Go_StructuredFields_Safe(t *testing.T) {
	// zerolog/zap structured-field calls escape values — must NOT fire even
	// though r.URL appears in the line (the reLogGoStructuredFields skip).
	content := `log.Info().Str("query", r.URL.RawQuery).Msg("request")`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Go_Zap_Fires(t *testing.T) {
	content := `sugar.Errorf("bad form: %s", r.FormValue("x"))`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Java_SysOut_Fires(t *testing.T) {
	content := `System.out.println("Param: " + request.getParameter("name"));`
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Java_Slf4j_Header_Fires(t *testing.T) {
	content := `log.warn("ua: {}", request.getHeader("User-Agent"));`
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Comment_Skipped(t *testing.T) {
	content := `# logging.info("q: %s", request.args.get('q'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_DefaultLanguage_NoFindings(t *testing.T) {
	// A language outside the switch (e.g. Rust) hits the default branch and
	// returns no findings.
	r := UnsanitizedLogInput{}
	findings := scanDirect(r, rules.LangRust, "/app/main.rs",
		`logger.info("user input: " + request_param);`)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for unsupported language, got %d", len(findings))
	}
}

func TestLOG001_Metadata(t *testing.T) {
	r := UnsanitizedLogInput{}
	if r.ID() != "BATOU-LOG-001" {
		t.Errorf("ID = %q", r.ID())
	}
	if r.DefaultSeverity() != rules.High {
		t.Errorf("severity = %v, want High", r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description should be non-empty")
	}
	if len(r.Languages()) == 0 {
		t.Error("Languages should be non-empty")
	}
	findings := scanDirect(r, rules.LangPython, "/app/v.py",
		`logging.error("bad: %s", request.args.get('q'))`)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	f := findings[0]
	if f.CWEID != "CWE-117" {
		t.Errorf("CWEID = %q, want CWE-117", f.CWEID)
	}
	if f.LineNumber != 1 {
		t.Errorf("LineNumber = %d, want 1", f.LineNumber)
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-002 additional branch coverage
// ---------------------------------------------------------------------------

func TestLOG002_PHP_Concat_Fires(t *testing.T) {
	content := `<?php error_log("input: " . $_GET['x']); ?>`
	result := testutil.ScanContent(t, "/app/h.php", content)
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-001", "BATOU-LOG-002")
}

func TestLOG002_Ruby_Interp_Fires(t *testing.T) {
	content := `logger.error("p: #{params[:id]}")`
	result := testutil.ScanContent(t, "/app/c.rb", content)
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-001", "BATOU-LOG-002")
}

func TestLOG002_Sanitized_LineSkipped(t *testing.T) {
	// reLogSanitized engages: an inline strip/sanitize keyword on the line
	// suppresses LOG-002.
	content := `logger.error("user=" + sanitize(req.body.user))`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-002")
}

func TestLOG002_Comment_Skipped(t *testing.T) {
	content := `// log.Info(fmt.Sprintf("s: %s", r.URL.Query().Get("q")))`
	result := testutil.ScanContent(t, "/app/h.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-002")
}

func TestLOG002_DefaultLanguage_NoFindings(t *testing.T) {
	r := CRLFLogInjection{}
	findings := scanDirect(r, rules.LangRust, "/app/m.rs",
		`log.info("user=" + request.body)`)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestLOG002_Metadata(t *testing.T) {
	r := CRLFLogInjection{}
	if r.ID() != "BATOU-LOG-002" || r.DefaultSeverity() != rules.High {
		t.Errorf("unexpected metadata: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" || len(r.Languages()) == 0 {
		t.Error("metadata should be populated")
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-003 additional branch coverage
// ---------------------------------------------------------------------------

func TestLOG003_JSON_Skipped_ByLanguage(t *testing.T) {
	r := SensitiveDataInLogs{}
	findings := scanDirect(r, rules.LangJSON, "/app/data.json",
		`logger.info("password: " + secretValue)`)
	if len(findings) != 0 {
		t.Fatalf("JSON language should be skipped, got %d findings", len(findings))
	}
}

func TestLOG003_JSON_Skipped_BySuffix(t *testing.T) {
	// Language is LangAny but the .json suffix path triggers the skip.
	r := SensitiveDataInLogs{}
	findings := scanDirect(r, rules.LangAny, "/app/strings.JSON",
		`logger.info("password: " + secretValue)`)
	if len(findings) != 0 {
		t.Fatalf(".json suffix should be skipped, got %d findings", len(findings))
	}
}

func TestLOG003_PHP_BothPatterns(t *testing.T) {
	content := `<?php Log::error("secret leak: " . $secret); ?>`
	result := testutil.ScanContent(t, "/app/a.php", content)
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG003_StaticMessageGate_NoFinding(t *testing.T) {
	// "password" appears only inside a single static literal message → the
	// logArgIsOnlyStringMessage gate suppresses LOG-003.
	r := SensitiveDataInLogs{}
	findings := scanDirect(r, rules.LangGo, "/app/h.go",
		`log.Info("please change your password soon")`)
	if hasRule(findings, "BATOU-LOG-003") {
		t.Fatal("static-message keyword should be gated out of LOG-003")
	}
}

func TestLOG003_Comment_Skipped(t *testing.T) {
	r := SensitiveDataInLogs{}
	findings := scanDirect(r, rules.LangGo, "/app/h.go",
		`// log.Info("password: " + pw)`)
	if hasRule(findings, "BATOU-LOG-003") {
		t.Fatal("comment line should be skipped")
	}
}

func TestLOG003_Metadata(t *testing.T) {
	r := SensitiveDataInLogs{}
	if r.ID() != "BATOU-LOG-003" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("unexpected metadata: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	findings := scanDirect(r, rules.LangGo, "/app/h.go",
		`log.Info("api_key=" + apiKey)`)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if findings[0].CWEID != "CWE-532" {
		t.Errorf("CWEID = %q, want CWE-532", findings[0].CWEID)
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-004: LoggingSecrets
// ---------------------------------------------------------------------------

func TestLOG004_Concat_Fires(t *testing.T) {
	content := `logger.info("client_secret=" + clientSecret)`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-004")
}

func TestLOG004_JSON_Skipped(t *testing.T) {
	r := &LoggingSecrets{}
	findings := scanDirect(r, rules.LangJSON, "/app/x.json",
		`log.info("password=" + pw)`)
	if len(findings) != 0 {
		t.Fatalf("JSON should be skipped, got %d", len(findings))
	}
}

func TestLOG004_StaticMessage_Gated(t *testing.T) {
	content := `console.debug('updating saved access_token')`
	result := testutil.ScanContent(t, "/app/s.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-004")
}

func TestLOG004_Comment_Skipped(t *testing.T) {
	content := `// logger.info("password=" + pw)`
	result := testutil.ScanContent(t, "/app/a.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-004")
}

func TestLOG004_LongMatch_Truncated(t *testing.T) {
	// Force the >120-char truncation branch in LoggingSecrets.Scan. The match
	// span runs from the logger call to the credential keyword, so the filler
	// must precede the keyword to lengthen the span. Use concatenation (not a
	// single static literal) so the logArgIsOnlyStringMessage gate does not
	// suppress it.
	long := strings.Repeat("x", 200)
	content := `logger.info("` + long + `" + password)`
	r := &LoggingSecrets{}
	findings := scanDirect(r, rules.LangGo, "/app/h.go", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	mt := findings[0].MatchedText
	if !strings.HasSuffix(mt, "...") {
		t.Errorf("expected truncated MatchedText ending in ..., got len %d", len(mt))
	}
}

func TestLOG004_Metadata(t *testing.T) {
	r := &LoggingSecrets{}
	if r.ID() != "BATOU-LOG-004" || r.DefaultSeverity() != rules.High {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("name/description empty")
	}
	if len(r.Languages()) == 0 || r.Languages()[0] != rules.LangAny {
		t.Error("expected LangAny")
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-005: LoggingPII
// ---------------------------------------------------------------------------

func TestLOG005_Email_Fires(t *testing.T) {
	content := `logger.info("user email: " + user_email)`
	result := testutil.ScanContent(t, "/app/h.go", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-005")
}

func TestLOG005_SSN_Fires(t *testing.T) {
	content := `console.log("ssn:", ssn)`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-005")
}

func TestLOG005_NonPII_Safe(t *testing.T) {
	content := `logger.info("username: " + username)`
	result := testutil.ScanContent(t, "/app/h.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-005")
}

func TestLOG005_Comment_Skipped(t *testing.T) {
	content := `# logger.info("ssn: " + ssn)`
	result := testutil.ScanContent(t, "/app/h.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-005")
}

func TestLOG005_LongMatch_Truncated(t *testing.T) {
	long := strings.Repeat("y", 200)
	content := `logger.info("` + long + ` credit_card")`
	r := &LoggingPII{}
	findings := scanDirect(r, rules.LangGo, "/app/h.go", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.HasSuffix(findings[0].MatchedText, "...") {
		t.Error("expected truncated MatchedText")
	}
}

func TestLOG005_Metadata(t *testing.T) {
	r := &LoggingPII{}
	if r.ID() != "BATOU-LOG-005" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	findings := scanDirect(r, rules.LangGo, "/app/h.go", `log.info("dob=" + dob)`)
	if len(findings) == 0 || findings[0].CWEID != "CWE-532" {
		t.Errorf("expected CWE-532 finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-006: LogInjectionUserInput
// ---------------------------------------------------------------------------

func TestLOG006_Concat_Fires(t *testing.T) {
	content := `logger.info("user=" + userInput)`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-006")
}

func TestLOG006_Format_Fires(t *testing.T) {
	content := `log.Infof("query=%s", queryParam)`
	result := testutil.ScanContent(t, "/app/h.go", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-006")
}

func TestLOG006_NewlineStripped_Safe(t *testing.T) {
	// reNewlineStrip engages (strip keyword) → suppressed.
	content := `logger.info("user=" + userInput.strip())`
	result := testutil.ScanContent(t, "/app/h.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-006")
}

func TestLOG006_Comment_Skipped(t *testing.T) {
	content := `// logger.info("user=" + userInput)`
	result := testutil.ScanContent(t, "/app/h.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-006")
}

func TestLOG006_LongMatch_Truncated(t *testing.T) {
	// Span runs from the call through the "+" marker and on to the user-input
	// keyword (the trailing `.*` is greedy), so filler before the keyword
	// lengthens the match.
	long := strings.Repeat("z", 200)
	content := `logger.info("u=" + ` + long + ` userParam)`
	r := &LogInjectionUserInput{}
	findings := scanDirect(r, rules.LangGo, "/app/h.go", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.HasSuffix(findings[0].MatchedText, "...") {
		t.Error("expected truncated MatchedText")
	}
}

func TestLOG006_Metadata(t *testing.T) {
	r := &LogInjectionUserInput{}
	if r.ID() != "BATOU-LOG-006" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	findings := scanDirect(r, rules.LangGo, "/app/h.go", `log.Infof("q=%s", queryParam)`)
	if len(findings) == 0 || findings[0].CWEID != "CWE-117" {
		t.Errorf("expected CWE-117 finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-007: StackTraceToClient
// ---------------------------------------------------------------------------

func TestLOG007_StackToClient_Fires(t *testing.T) {
	content := `res.send(err.stack);`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-007")
}

func TestLOG007_Traceback_Python_Fires(t *testing.T) {
	content := `return JsonResponse({"trace": traceback.format_exc()})`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-007")
}

func TestLOG007_Safe_GenericError(t *testing.T) {
	content := `res.json({error: "Internal server error", requestId: id});`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-007")
}

func TestLOG007_Comment_Skipped(t *testing.T) {
	content := `// res.send(err.stack)`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-007")
}

func TestLOG007_LongMatch_Truncated(t *testing.T) {
	// Span runs from res.send( through the inner [^)]* up to the `.stack`
	// keyword, so filler before the keyword lengthens it.
	long := strings.Repeat("a", 200)
	content := `res.send("` + long + `" + err.stack)`
	r := &StackTraceToClient{}
	findings := scanDirect(r, rules.LangJavaScript, "/app/h.js", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.HasSuffix(findings[0].MatchedText, "...") {
		t.Error("expected truncated MatchedText")
	}
}

func TestLOG007_Metadata(t *testing.T) {
	r := &StackTraceToClient{}
	if r.ID() != "BATOU-LOG-007" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" || len(r.Languages()) == 0 {
		t.Error("metadata should be populated")
	}
	findings := scanDirect(r, rules.LangJavaScript, "/app/h.js", `res.json(err.stack)`)
	if len(findings) == 0 || findings[0].CWEID != "CWE-209" {
		t.Errorf("expected CWE-209 finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-008: DebugLoggingInProd
// ---------------------------------------------------------------------------

func TestLOG008_DebugLevel_Fires(t *testing.T) {
	content := `LOG_LEVEL=DEBUG`
	result := testutil.ScanContent(t, "/app/config.env", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-008")
}

func TestLOG008_ProdContext_HighConfidence(t *testing.T) {
	// Prod context in the file path elevates confidence to high.
	r := &DebugLoggingInProd{}
	findings := scanDirect(r, rules.LangAny, "/app/config.prod.yaml", `log_level: "trace"`)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if findings[0].Confidence != "high" {
		t.Errorf("expected high confidence in prod path, got %q", findings[0].Confidence)
	}
}

func TestLOG008_NonProd_MediumConfidence(t *testing.T) {
	r := &DebugLoggingInProd{}
	findings := scanDirect(r, rules.LangAny, "/app/dev.env", `LOG_LEVEL=DEBUG`)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if findings[0].Confidence != "medium" {
		t.Errorf("expected medium confidence, got %q", findings[0].Confidence)
	}
}

func TestLOG008_ProdContentElevates(t *testing.T) {
	// Prod keyword in the content (not the path) also elevates confidence.
	r := &DebugLoggingInProd{}
	content := "environment = production\nLOG_LEVEL=DEBUG"
	findings := scanDirect(r, rules.LangAny, "/app/settings.cfg", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if findings[0].Confidence != "high" {
		t.Errorf("expected high confidence with prod content, got %q", findings[0].Confidence)
	}
}

func TestLOG008_InfoLevel_Safe(t *testing.T) {
	content := `LOG_LEVEL=INFO`
	result := testutil.ScanContent(t, "/app/config.env", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-008")
}

func TestLOG008_Comment_Skipped(t *testing.T) {
	r := &DebugLoggingInProd{}
	findings := scanDirect(r, rules.LangAny, "/app/c.cfg", `# LOG_LEVEL=DEBUG`)
	if len(findings) != 0 {
		t.Fatalf("comment line should be skipped, got %d", len(findings))
	}
}

func TestLOG008_LongMatch_Truncated(t *testing.T) {
	// The match ends at the level token, so trailing text does not lengthen
	// the span; instead pad the \s* between the key and "=DEBUG".
	content := `LOG_LEVEL` + strings.Repeat(" ", 140) + `=DEBUG`
	r := &DebugLoggingInProd{}
	findings := scanDirect(r, rules.LangAny, "/app/c.cfg", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.HasSuffix(findings[0].MatchedText, "...") {
		t.Error("expected truncated MatchedText")
	}
}

func TestLOG008_Metadata(t *testing.T) {
	r := &DebugLoggingInProd{}
	if r.ID() != "BATOU-LOG-008" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" || len(r.Languages()) == 0 {
		t.Error("metadata should be populated")
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-009: LoggingRequestBodies
// ---------------------------------------------------------------------------

func TestLOG009_ReqBody_JS_Fires(t *testing.T) {
	content := `logger.info(req.body)`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-009")
}

func TestLOG009_RBody_Go_Fires(t *testing.T) {
	content := `log.Println(r.Body)`
	result := testutil.ScanContent(t, "/app/h.go", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-009")
}

func TestLOG009_Safe_NoRequestBody(t *testing.T) {
	content := `logger.info("status ok")`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-009")
}

func TestLOG009_Comment_Skipped(t *testing.T) {
	content := `// logger.info(req.body)`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-009")
}

func TestLOG009_LongMatch_Truncated(t *testing.T) {
	// Span runs from the call through [^)]* up to req.body, so filler before
	// the marker lengthens it.
	long := strings.Repeat("c", 200)
	content := `logger.info("` + long + `", req.body)`
	r := &LoggingRequestBodies{}
	findings := scanDirect(r, rules.LangJavaScript, "/app/h.js", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.HasSuffix(findings[0].MatchedText, "...") {
		t.Error("expected truncated MatchedText")
	}
}

func TestLOG009_Metadata(t *testing.T) {
	r := &LoggingRequestBodies{}
	if r.ID() != "BATOU-LOG-009" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	findings := scanDirect(r, rules.LangGo, "/app/h.go", `log.Println(r.Body)`)
	if len(findings) == 0 || findings[0].CWEID != "CWE-532" {
		t.Errorf("expected CWE-532 finding, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-010: ExcessiveLogging
// ---------------------------------------------------------------------------

func TestLOG010_FullObject_Fires(t *testing.T) {
	content := `console.log(JSON.stringify(req))`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-010")
}

func TestLOG010_EveryRequest_Fires(t *testing.T) {
	content := `logger.info("logging every request now")`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-010")
}

func TestLOG010_Python_Repr_Fires(t *testing.T) {
	content := `logging.info(repr(request))`
	result := testutil.ScanContent(t, "/app/h.py", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-010")
}

func TestLOG010_Safe_SelectedFields(t *testing.T) {
	content := `console.log({method: req.method, path: req.path})`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-010")
}

func TestLOG010_Comment_Skipped(t *testing.T) {
	content := `// console.log(JSON.stringify(req))`
	result := testutil.ScanContent(t, "/app/h.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-010")
}

func TestLOG010_LongMatch_Truncated(t *testing.T) {
	// reLogEveryRequest branch with a long match, exercising the truncation
	// inside the second-pattern path. The span ends at "request", so the
	// filler must sit between the call and "every".
	long := strings.Repeat("d", 200)
	content := `console.log("` + long + ` every request")`
	r := &ExcessiveLogging{}
	findings := scanDirect(r, rules.LangJavaScript, "/app/h.js", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.HasSuffix(findings[0].MatchedText, "...") {
		t.Error("expected truncated MatchedText")
	}
}

func TestLOG010_Metadata(t *testing.T) {
	r := &ExcessiveLogging{}
	if r.ID() != "BATOU-LOG-010" || r.DefaultSeverity() != rules.Low {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" || len(r.Languages()) == 0 {
		t.Error("metadata should be populated")
	}
}

// ---------------------------------------------------------------------------
// BATOU-LOG-011: MissingAuditLogging (DEFINED but NOT registered in init() —
// must be exercised via direct Scan()).
// ---------------------------------------------------------------------------

func TestLOG011_MissingAudit_Fires(t *testing.T) {
	// Security event with no audit logging and no log call within window.
	content := `func login(user, pass string) error {
	if !checkCredentials(user, pass) {
		return errors.New("bad")
	}
	return nil
}`
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangGo, "/app/auth.go", content)
	if !hasRule(findings, "BATOU-LOG-011") {
		t.Fatalf("expected BATOU-LOG-011, got %v", findings)
	}
	if findings[0].CWEID != "CWE-778" {
		t.Errorf("CWEID = %q, want CWE-778", findings[0].CWEID)
	}
}

func TestLOG011_AuditPresent_NoFinding(t *testing.T) {
	// audit_log call present in file → whole rule short-circuits.
	content := `func login(user, pass string) error {
	audit_log("login attempt", user)
	return nil
}`
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangGo, "/app/auth.go", content)
	if hasRule(findings, "BATOU-LOG-011") {
		t.Fatal("audit logging present → should not fire")
	}
}

func TestLOG011_LoggingNearEvent_NoFinding(t *testing.T) {
	// A generic log call within the 15-line window after the event suppresses.
	content := `func resetPassword(user string) error {
	logger.info("reset requested")
	return nil
}`
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangGo, "/app/auth.go", content)
	if hasRule(findings, "BATOU-LOG-011") {
		t.Fatal("nearby log call → should not fire")
	}
}

func TestLOG011_NoSecurityEvent_NoFinding(t *testing.T) {
	// File contains no security-event keyword → early return.
	content := `func computeSum(a, b int) int {
	return a + b
}`
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangGo, "/app/math.go", content)
	if len(findings) != 0 {
		t.Fatalf("no security event → expected 0 findings, got %d", len(findings))
	}
}

func TestLOG011_YAML_Skipped(t *testing.T) {
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangYAML, "/app/conf.yaml", `login: enabled`)
	if len(findings) != 0 {
		t.Fatalf("YAML should be skipped, got %d", len(findings))
	}
}

func TestLOG011_JSON_Skipped(t *testing.T) {
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangJSON, "/app/conf.json", `{"login": true}`)
	if len(findings) != 0 {
		t.Fatalf("JSON should be skipped, got %d", len(findings))
	}
}

func TestLOG011_SQL_Skipped(t *testing.T) {
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangSQL, "/app/q.sql", `SELECT * FROM login_attempts`)
	if len(findings) != 0 {
		t.Fatalf("SQL should be skipped, got %d", len(findings))
	}
}

func TestLOG011_ClientSideJS_Skipped(t *testing.T) {
	// JS with no server-side API markers → IsServerSideCode false → skipped.
	r := &MissingAuditLogging{}
	content := `function login() { document.getElementById("x"); }`
	findings := scanDirect(r, rules.LangJavaScript, "/app/client.js", content)
	if len(findings) != 0 {
		t.Fatalf("client-side JS should be skipped, got %d", len(findings))
	}
}

func TestLOG011_CommentEvent_Skipped(t *testing.T) {
	// The only security-event keyword is on a comment line → the per-line
	// loop skips it, so no finding even though the file matches at file level.
	content := `package main
// login handler will be added later
func placeholder() {
	doNothing()
}`
	r := &MissingAuditLogging{}
	findings := scanDirect(r, rules.LangGo, "/app/auth.go", content)
	if hasRule(findings, "BATOU-LOG-011") {
		t.Fatal("comment-only security event should not fire")
	}
}

func TestLOG011_Metadata(t *testing.T) {
	r := &MissingAuditLogging{}
	if r.ID() != "BATOU-LOG-011" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("metadata mismatch: id=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" || len(r.Languages()) == 0 {
		t.Error("metadata should be populated")
	}
}
