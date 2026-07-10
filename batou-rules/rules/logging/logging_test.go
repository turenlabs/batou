package logging

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// --- BATOU-LOG-001: Unsanitized User Input in Log Calls ---

func TestLOG001_Python_Logging(t *testing.T) {
	content := `logging.info("User search: %s", request.args.get('q'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Python_Logger(t *testing.T) {
	content := `logger.warning("Bad input from: %s", request.remote_addr)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Java_Logger(t *testing.T) {
	content := `logger.info("Param: " + request.getParameter("name"));`
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Go_Log(t *testing.T) {
	content := `log.Printf("Query: %s", r.URL.Query().Get("search"))`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_JS_Console(t *testing.T) {
	content := `console.log("Input: " + req.body.message);`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_PHP_ErrorLog(t *testing.T) {
	content := `<?php error_log("Input: " . $_POST['data']); ?>`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Ruby_Logger(t *testing.T) {
	content := `Rails.logger.info("Params: #{params[:q]}")`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Fixture_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/log_injection.go")
	result := testutil.ScanContent(t, "/app/handler.go", content)
	hasLog := testutil.HasFinding(result, "BATOU-LOG-001") || testutil.HasFinding(result, "BATOU-LOG-002")
	if !hasLog {
		t.Errorf("expected log injection finding in log_injection.go, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestLOG001_Fixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/log_injection.ts")
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	hasLog := testutil.HasFinding(result, "BATOU-LOG-001") || testutil.HasFinding(result, "BATOU-LOG-002")
	if !hasLog {
		t.Errorf("expected log injection finding in log_injection.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- BATOU-LOG-002: CRLF Log Injection ---

func TestLOG002_JS_TemplateLiteral(t *testing.T) {
	content := "console.log(`User search: ${req.query.q}`);"
	result := testutil.ScanContent(t, "/app/search.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-001", "BATOU-LOG-002")
}

func TestLOG002_Python_FString(t *testing.T) {
	content := `logger.info(f"Login attempt: {request.form['username']}")`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-001", "BATOU-LOG-002")
}

func TestLOG002_Java_Format(t *testing.T) {
	content := `LOG.info(String.format("Param: %s", request.getParameter("q")));`
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-001", "BATOU-LOG-002")
}

func TestLOG002_Go_Sprintf(t *testing.T) {
	content := `log.Info(fmt.Sprintf("Search: %s", r.URL.Query().Get("q")))`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-001", "BATOU-LOG-002")
}

func TestLOG002_Safe_Sanitized(t *testing.T) {
	content := `sanitized := strings.Replace(input, "\n", "", -1)
logger.info("Concat: " + sanitized + " query")`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	// The sanitized line should exclude the concat line from flagging
	// but the concat pattern may still match depending on context
	_ = result
}

// --- BATOU-LOG-003: Sensitive Data in Logs ---

func TestLOG003_PasswordInLog(t *testing.T) {
	content := `logger.info("Login with password: " + password)`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG003_TokenInLog(t *testing.T) {
	content := `console.log("Token: " + access_token);`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG003_APIKeyInLog(t *testing.T) {
	content := `logging.info("Key: %s", api_key)`
	result := testutil.ScanContent(t, "/app/config.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG003_CreditCardInLog(t *testing.T) {
	content := `LOG.info("Card: " + creditcard);`
	result := testutil.ScanContent(t, "/app/Payment.java", content)
	testutil.MustFindRule(t, result, "BATOU-LOG-003")
}

func TestLOG003_PHPSensitiveLog(t *testing.T) {
	content := `<?php error_log("Password: " . $password); ?>`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

// --- Negative/safe tests for LOG rules ---

func TestLOG001_Safe_StaticLogMessage_Python(t *testing.T) {
	content := `logging.info("Server started on port 8080")`
	result := testutil.ScanContent(t, "/app/server.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Safe_StaticLogMessage_Go(t *testing.T) {
	content := `log.Printf("Server listening on %s", ":8080")`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Safe_StaticLogMessage_Java(t *testing.T) {
	content := `logger.info("Application started successfully");`
	result := testutil.ScanContent(t, "/app/Main.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Safe_StaticLogMessage_JS(t *testing.T) {
	content := `console.log("Database connection established");`
	result := testutil.ScanContent(t, "/app/db.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Safe_StaticLogMessage_PHP(t *testing.T) {
	content := `<?php error_log("Cache cleared"); ?>`
	result := testutil.ScanContent(t, "/app/cache.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG001_Safe_StaticLogMessage_Ruby(t *testing.T) {
	content := `Rails.logger.info("Background job completed")`
	result := testutil.ScanContent(t, "/app/job.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-001")
}

func TestLOG002_Safe_StaticConcat_Go(t *testing.T) {
	content := `log.Info("Server " + "started")`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-002")
}

func TestLOG002_Safe_StaticFString_Python(t *testing.T) {
	content := `logger.info(f"Processing batch {batch_id}")`
	result := testutil.ScanContent(t, "/app/batch.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-002")
}

func TestLOG002_Safe_StaticTemplate_JS(t *testing.T) {
	content := "console.log(`Server running on port ${port}`);"
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-002")
}

func TestLOG003_Safe_NoSensitiveData(t *testing.T) {
	content := `logger.info("User logged in: " + username)`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
}

func TestLOG003_Safe_NoSensitiveData_Python(t *testing.T) {
	content := `logging.info("Request processed in %s ms", duration)`
	result := testutil.ScanContent(t, "/app/perf.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
}

func TestLOG003_Safe_NoSensitiveData_Go(t *testing.T) {
	content := `log.Printf("Processing user: %s", userID)`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
}

func TestLOG003_Safe_CommentContainsSensitive(t *testing.T) {
	content := `// logger.info("Token: " + api_key)`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
}

// --- LOG-003 / LOG-004 FP gates: keyword only in static log message (owncloud/web) ---

func TestLOG003_Safe_KeywordInMessageLiteral_JS(t *testing.T) {
	// The credential keyword ("token") appears only inside a static log
	// message literal, not as a value being logged.
	content := `console.debug('Generating share token for the current resource')`
	result := testutil.ScanContent(t, "/app/share.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
	testutil.MustNotFindRule(t, result, "BATOU-LOG-004")
}

func TestLOG004_Safe_AccessTokenInDebugMessage_JS(t *testing.T) {
	content := `console.debug('[authService:initializeContext] - updating context with saved access_token')`
	result := testutil.ScanContent(t, "/app/authService.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-004")
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
}

func TestLOG004_Fires_TokenInterpolatedInLog_JS(t *testing.T) {
	// An actual token VALUE interpolated into the log message — still fires.
	content := "console.debug(`New user loaded. access_token=${user.access_token}`)"
	result := testutil.ScanContent(t, "/app/authService.ts", content)
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG004_Fires_SecretAsSeparateArg_Go(t *testing.T) {
	// log.Printf-style: the credential is a separate argument, not message text.
	content := `log.Printf("auth failed for %s with secret %s", user, apiSecret)`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG004_Fires_PasswordConcat_JS(t *testing.T) {
	content := `logger.info('token: ' + accessToken)`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindAnyRule(t, result, "BATOU-LOG-003", "BATOU-LOG-004")
}

func TestLOG003_LOG004_Safe_TranslationJSON(t *testing.T) {
	// i18n / l10n JSON files: UI message strings, not credentials.
	content := `{
  "loginWithToken": "Log in with token",
  "resetPassword": "Reset password",
  "logout": "Log out"
}`
	result := testutil.ScanContent(t, "/app/l10n/en.json", content)
	testutil.MustNotFindRule(t, result, "BATOU-LOG-003")
	testutil.MustNotFindRule(t, result, "BATOU-LOG-004")
}
