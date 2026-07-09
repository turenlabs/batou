package auth

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ===========================================================================
// BATOU-AUTH-008: Missing Rate Limiting on Login
// ===========================================================================

func TestAUTH008_Express_LoginNoRateLimit(t *testing.T) {
	content := `app.post('/login', (req, res) => {
	const { user, pass } = req.body;
	authenticate(user, pass);
});`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-008")
}

func TestAUTH008_Safe_WithRateLimit(t *testing.T) {
	// File mentions a rate limiter, so the rule is suppressed file-wide.
	content := `const rateLimit = require('express-rate-limit');
app.post('/login', loginLimiter, (req, res) => {
	authenticate(req.body.user, req.body.pass);
});`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-008")
}

func TestAUTH008_Safe_NonLoginRoute(t *testing.T) {
	content := `app.post('/products', (req, res) => { createProduct(req.body); });`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-008")
}

// ===========================================================================
// BATOU-AUTH-009: Password Comparison Using == (Timing Attack)
// ===========================================================================

func TestAUTH009_Go_PasswordEquals(t *testing.T) {
	content := `func check(password string) bool {
	if password == storedPassword {
		return true
	}
	return false
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-009")
}

func TestAUTH009_JS_PasswordTripleEquals(t *testing.T) {
	content := `function login(pass) {
	return pass === expectedPass;
}`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-009")
}

func TestAUTH009_Python_PasswordEquals(t *testing.T) {
	content := `def verify(password):
    return password == stored_hash`
	result := testutil.ScanContent(t, "/app/verify.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-009")
}

func TestAUTH009_Safe_ConstantTimeCompare(t *testing.T) {
	// Presence of a safe-compare primitive suppresses the rule for the file.
	content := `import hmac
def verify(password):
    expected = stored_hash
    if password == expected:
        return hmac.compare_digest(password, expected)
    return False`
	result := testutil.ScanContent(t, "/app/verify.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-009")
}

func TestAUTH009_Safe_CommentLineIgnored(t *testing.T) {
	// A `==` comparison inside a comment must not trigger.
	content := `func check(password string) bool {
	// legacy code did password == "x" but we removed it
	return bcrypt.CompareHashAndPassword(h, p) == nil
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-009")
}

// ===========================================================================
// BATOU-AUTH-010: Hardcoded Admin/Default Credentials
// ===========================================================================

func TestAUTH010_HardcodedAdmin(t *testing.T) {
	content := `config = { admin: "admin" }`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-010")
}

func TestAUTH010_DefaultPassword(t *testing.T) {
	content := `default_password = "changeme123"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-010")
}

func TestAUTH010_Safe_NoDefaultCreds(t *testing.T) {
	content := `admin_password = os.environ["ADMIN_PASSWORD"]`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-010")
}

func TestAUTH010_Safe_CommentLine(t *testing.T) {
	content := `# admin = "admin" was the old default, removed`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-010")
}

// ===========================================================================
// BATOU-AUTH-012: Auth Bypass via Parameter Manipulation
// ===========================================================================

func TestAUTH012_IsAdminFromReqBody(t *testing.T) {
	content := `const isAdmin = req.body.isAdmin;`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-012")
}

func TestAUTH012_RoleFromRequestPOST(t *testing.T) {
	content := `role = request.POST['role']`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-012")
}

func TestAUTH012_PHP_AdminFromRequest(t *testing.T) {
	content := `<?php $is_admin = $_GET['is_admin']; ?>`
	result := testutil.ScanContent(t, "/app/index.php", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-012")
}

func TestAUTH012_Safe_RoleFromSession(t *testing.T) {
	content := `const isAdmin = req.session.user.role === 'admin';`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-012")
}

// ===========================================================================
// BATOU-AUTH-013: Broken Function-Level Access Control
// ===========================================================================

func TestAUTH013_AdminEndpointNoCheck(t *testing.T) {
	content := `app.get('/admin/users', (req, res) => {
	res.json(db.allUsers());
});`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-013")
}

func TestAUTH013_Safe_WithAccessControl(t *testing.T) {
	// File contains an access-control primitive, suppressing the rule.
	content := `function requireAdmin(req, res, next) { next(); }
app.get('/admin/users', requireAdmin, (req, res) => {
	res.json(db.allUsers());
});`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-013")
}

func TestAUTH013_Safe_NonAdminRoute(t *testing.T) {
	content := `app.get('/public/info', (req, res) => { res.json(info); });`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-013")
}

// ===========================================================================
// BATOU-AUTH-014: Insecure Password Reset (Predictable Token)
// ===========================================================================

func TestAUTH014_PredictableResetToken(t *testing.T) {
	content := `function generateResetToken() {
	const reset_token = Math.random().toString(36);
	return reset_token;
}`
	result := testutil.ScanContent(t, "/app/reset.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-014")
}

func TestAUTH014_Python_TimeBasedResetToken(t *testing.T) {
	content := `def forgot_password(email):
    token = random.randint(1000, 9999)
    return token`
	result := testutil.ScanContent(t, "/app/reset.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-014")
}

func TestAUTH014_Safe_SecureToken(t *testing.T) {
	// Secure token generation present -> rule suppressed even with reset context.
	content := `def reset_password(email):
    token = secrets.token_urlsafe(32)
    other = random.randint(1, 9)
    return token`
	result := testutil.ScanContent(t, "/app/reset.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-014")
}

func TestAUTH014_Safe_NoResetContext(t *testing.T) {
	// Predictable randomness but no password-reset context -> no finding.
	content := `function pickColor() { return Math.random(); }`
	result := testutil.ScanContent(t, "/app/ui.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-014")
}

// ===========================================================================
// BATOU-AUTH-015: Missing MFA Check
// ===========================================================================

func TestAUTH015_SensitiveOpNoMFA(t *testing.T) {
	content := `app.post('/transfer', (req, res) => {
	doTransfer(req.body.amount);
});`
	result := testutil.ScanContent(t, "/app/payments.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-015")
}

func TestAUTH015_Safe_WithMFA(t *testing.T) {
	// File references MFA, suppressing the rule entirely.
	content := `app.post('/transfer', (req, res) => {
	if (!verifyTotp(req.body.otp)) return res.status(403).end();
	doTransfer(req.body.amount);
});`
	result := testutil.ScanContent(t, "/app/payments.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-015")
}

func TestAUTH015_Safe_SensitiveWordNoRoute(t *testing.T) {
	// "transfer" appears but there is no HTTP route shape nearby, so the
	// MFA rule must not fire (avoids flagging plain internal functions).
	content := `func transferInternalBalance(a, b int) int {
	return a + b
}`
	result := testutil.ScanContent(t, "/app/ledger.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-015")
}

// ===========================================================================
// BATOU-AUTH-016: Username Enumeration via Different Error Messages
// ===========================================================================

func TestAUTH016_DifferentErrorMessages(t *testing.T) {
	content := `def login(user, pw):
    if not user_exists(user):
        raise Error("user not found")
    if not check_pw(pw):
        raise Error("wrong password")`
	result := testutil.ScanContent(t, "/app/login.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-016")
}

func TestAUTH016_Safe_OnlyOneMessage(t *testing.T) {
	// Only a "user not found" message and no distinct wrong-password message.
	content := `def login(user, pw):
    if not authenticate(user, pw):
        raise Error("user not found")`
	result := testutil.ScanContent(t, "/app/login.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-016")
}

func TestAUTH016_Safe_GenericMessage(t *testing.T) {
	content := `def login(user, pw):
    if not authenticate(user, pw):
        raise Error("Invalid username or password")`
	result := testutil.ScanContent(t, "/app/login.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-016")
}

// ===========================================================================
// BATOU-AUTH-017: Weak Password Policy (No Complexity Requirement)
// ===========================================================================

func TestAUTH017_LengthOnlyNoComplexity(t *testing.T) {
	content := `password_config = {}
min_length = 8
validate(password_config)`
	result := testutil.ScanContent(t, "/app/policy.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-017")
}

func TestAUTH017_Safe_HasComplexity(t *testing.T) {
	// Complexity requirement present -> rule suppressed.
	content := `min_length = 8
require_uppercase = True
must_have_special_char = True`
	result := testutil.ScanContent(t, "/app/policy.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-017")
}

func TestAUTH017_Safe_NoLengthCheck(t *testing.T) {
	content := `def validate(pw):
    return bool(pw)`
	result := testutil.ScanContent(t, "/app/policy.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-017")
}

// ===========================================================================
// Rule metadata sanity checks for the extended rules. These exercise the
// trivial-but-uncovered metadata accessors that the pipeline relies on for
// reporting (ID/Name/Description/DefaultSeverity/Languages).
// ===========================================================================

func TestAUTHExt_RuleMetadata(t *testing.T) {
	type ruleMeta struct {
		r       rules.Rule
		wantID  string
		wantSev rules.Severity
	}
	cases := []ruleMeta{
		{&MissingRateLimit{}, "BATOU-AUTH-008", rules.Medium},
		{&TimingAttackComparison{}, "BATOU-AUTH-009", rules.High},
		{&HardcodedAdminCreds{}, "BATOU-AUTH-010", rules.Critical},
		{&MissingCSRF{}, "BATOU-AUTH-011", rules.High},
		{&AuthBypassParam{}, "BATOU-AUTH-012", rules.High},
		{&BrokenAccessControl{}, "BATOU-AUTH-013", rules.High},
		{&InsecurePasswordReset{}, "BATOU-AUTH-014", rules.High},
		{&MissingMFA{}, "BATOU-AUTH-015", rules.Medium},
		{&UsernameEnumeration{}, "BATOU-AUTH-016", rules.Medium},
		{&WeakPasswordPolicyExt{}, "BATOU-AUTH-017", rules.Medium},
	}
	for _, c := range cases {
		t.Run(c.wantID, func(t *testing.T) {
			if got := c.r.ID(); got != c.wantID {
				t.Errorf("ID() = %q, want %q", got, c.wantID)
			}
			if c.r.Name() == "" {
				t.Errorf("Name() empty for %s", c.wantID)
			}
			if c.r.Description() == "" {
				t.Errorf("Description() empty for %s", c.wantID)
			}
			if got := c.r.DefaultSeverity(); got != c.wantSev {
				t.Errorf("DefaultSeverity() = %v, want %v", got, c.wantSev)
			}
			if len(c.r.Languages()) == 0 {
				t.Errorf("Languages() empty for %s", c.wantID)
			}
		})
	}
}

// ===========================================================================
// BATOU-AUTH-011: Missing CSRF Protection — the rule is not registered in the
// pipeline (commented out), so it is exercised by calling Scan directly.
// ===========================================================================

func TestAUTH011_StateChangingNoCSRF(t *testing.T) {
	r := &MissingCSRF{}
	ctx := &rules.ScanContext{
		FilePath: "/app/routes.js",
		Content:  "app.post('/account/update', updateHandler);",
		Language: rules.LangJavaScript,
	}
	findings := r.Scan(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected BATOU-AUTH-011 finding for unprotected POST route")
	}
	if findings[0].RuleID != "BATOU-AUTH-011" {
		t.Errorf("RuleID = %q, want BATOU-AUTH-011", findings[0].RuleID)
	}
}

func TestAUTH011_Safe_WithCSRFToken(t *testing.T) {
	r := &MissingCSRF{}
	ctx := &rules.ScanContext{
		FilePath: "/app/routes.js",
		Content: `app.use(csrf());
app.post('/account/update', updateHandler);`,
		Language: rules.LangJavaScript,
	}
	if findings := r.Scan(ctx); len(findings) != 0 {
		t.Fatalf("expected no findings when csrf middleware present, got %d", len(findings))
	}
}

func TestAUTH011_Safe_JWTBearerImmune(t *testing.T) {
	r := &MissingCSRF{}
	ctx := &rules.ScanContext{
		FilePath: "/app/routes.js",
		Content: `const jwt = require('jsonwebtoken');
app.post('/account/update', updateHandler);`,
		Language: rules.LangJavaScript,
	}
	if findings := r.Scan(ctx); len(findings) != 0 {
		t.Fatalf("JWT bearer auth is CSRF-immune; expected 0 findings, got %d", len(findings))
	}
}

// ===========================================================================
// BATOU-AUTH-004: Session Fixation — also not registered, exercised directly.
// ===========================================================================

func TestAUTH004_Python_LoginNoRegen(t *testing.T) {
	r := &SessionFixation{}
	ctx := &rules.ScanContext{
		FilePath: "/app/views.py",
		Content: `def login(request):
    user = authenticate(request.POST['u'], request.POST['p'])
    request.session['user_id'] = user.id
    return redirect('/home')`,
		Language: rules.LangPython,
	}
	findings := r.Scan(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected session-fixation finding for login without session regeneration")
	}
	if findings[0].CWEID != "CWE-384" {
		t.Errorf("CWEID = %q, want CWE-384", findings[0].CWEID)
	}
}

func TestAUTH004_Python_Safe_CycleKey(t *testing.T) {
	r := &SessionFixation{}
	ctx := &rules.ScanContext{
		FilePath: "/app/views.py",
		Content: `def login(request):
    user = authenticate(request.POST['u'], request.POST['p'])
    request.session.cycle_key()
    request.session['user_id'] = user.id`,
		Language: rules.LangPython,
	}
	if findings := r.Scan(ctx); len(findings) != 0 {
		t.Fatalf("cycle_key() present; expected 0 findings, got %d", len(findings))
	}
}

func TestAUTH004_PHP_Safe_RegenerateID(t *testing.T) {
	r := &SessionFixation{}
	ctx := &rules.ScanContext{
		FilePath: "/app/login.php",
		Content: `<?php
function login($u, $p) {
    if (verify($u, $p)) {
        session_regenerate_id(true);
        $_SESSION['user'] = $u;
    }
}`,
		Language: rules.LangPHP,
	}
	if findings := r.Scan(ctx); len(findings) != 0 {
		t.Fatalf("session_regenerate_id present; expected 0 findings, got %d", len(findings))
	}
}

func TestAUTH004_Express_LoginNoRegen(t *testing.T) {
	r := &SessionFixation{}
	ctx := &rules.ScanContext{
		FilePath: "/app/auth.js",
		Content: `function login(req, res) {
    req.session.userId = lookup(req.body.user);
    res.redirect('/');
}`,
		Language: rules.LangJavaScript,
	}
	findings := r.Scan(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected session-fixation finding for express login without regenerate()")
	}
}

func TestAUTH004_Safe_JWTBearer(t *testing.T) {
	// Stateless bearer auth -> no server-side session to regenerate.
	r := &SessionFixation{}
	ctx := &rules.ScanContext{
		FilePath: "/app/auth.js",
		Content: `import jwt from 'jsonwebtoken';
function login(req, res) {
    const token = jwt.sign({ id: 1 }, secret);
    res.json({ token });
}`,
		Language: rules.LangJavaScript,
	}
	if findings := r.Scan(ctx); len(findings) != 0 {
		t.Fatalf("JWT bearer flow has no session; expected 0 findings, got %d", len(findings))
	}
}

// ===========================================================================
// BATOU-AUTH-001: JWT "none" algorithm path (separate finding within AUTH-001).
// ===========================================================================

func TestAUTH001_JWTNoneAlgorithm(t *testing.T) {
	content := `const payload = jwt.verify(token, key, { algorithms: ['none'] });`
	result := testutil.ScanContent(t, "/app/verify.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-001")
	// Confirm the JWT-none variant specifically fired (CWE-345), not just the
	// hardcoded-credential variant.
	found := false
	for _, f := range testutil.FindingsByRule(result, "BATOU-AUTH-001") {
		if f.CWEID == "CWE-345" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a CWE-345 (JWT none) finding within AUTH-001")
	}
}

// ===========================================================================
// BATOU-AUTH-003: CORS wildcard + credentials escalates to Critical.
// ===========================================================================

func TestAUTH003_WildcardWithCredentials_Critical(t *testing.T) {
	// Express cors() with wildcard origin AND credentials enabled. The
	// credentials regex matches "credentials: true", escalating to Critical.
	content := `app.use(cors({ origin: '*', credentials: true }));`
	result := testutil.ScanContent(t, "/app/cors.js", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-003")
	findings := testutil.FindingsByRule(result, "BATOU-AUTH-003")
	sawCritical := false
	for _, f := range findings {
		if f.Severity == rules.Critical {
			sawCritical = true
		}
	}
	if !sawCritical {
		t.Errorf("wildcard CORS + credentials should escalate to Critical; got %v", findings)
	}
}

// ===========================================================================
// BATOU-AUTH-006: JS/Python secure-flag paths (the secure-present branch).
// ===========================================================================

func TestAUTH006_JS_Safe_WithFlags(t *testing.T) {
	content := `res.cookie('session', token, {
	secure: true,
	httpOnly: true,
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-006")
}

func TestAUTH006_Python_CookieNoSecure(t *testing.T) {
	content := `response.set_cookie('session', token, max_age=3600)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-AUTH-006")
}

func TestAUTH006_Python_Safe_WithFlags(t *testing.T) {
	content := `response.set_cookie('session', token, secure=True, httponly=True)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-006")
}

func TestAUTH006_PHP_Safe_WithFlags(t *testing.T) {
	// PHP positional secure/httponly = true,true -> two "true" tokens -> safe.
	content := `<?php setcookie("session", $sid, time()+3600, "/", "", true, true); ?>`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-AUTH-006")
}

// ===========================================================================
// parseSmallInt direct unit tests (helper used by AUTH-005 length parsing).
// ===========================================================================

func TestParseSmallInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0", 0},
		{"7", 7},
		{"12", 12},
		{"100", 100},
		{"", 0},
		{"8a", 0}, // non-digit -> 0
		{"-5", 0}, // leading sign is non-digit -> 0
		{"3.5", 0},
	}
	for _, c := range cases {
		if got := parseSmallInt(c.in); got != c.want {
			t.Errorf("parseSmallInt(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// truncateExt helper (used by AUTH-015 finding text).
func TestTruncateExt(t *testing.T) {
	short := truncateExt("hello", 120)
	if short != "hello" {
		t.Errorf("truncateExt short = %q, want unchanged", short)
	}
	long := strings.Repeat("x", 200)
	got := truncateExt(long, 120)
	if len(got) != 123 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncateExt long: len=%d suffix-ok=%v", len(got), strings.HasSuffix(got, "..."))
	}
}
