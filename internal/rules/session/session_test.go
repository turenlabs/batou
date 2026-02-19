package session

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-SESS-001: Session fixation - no regeneration after login ---

func TestSESS001_Fixation_Python(t *testing.T) {
	content := `def login(request):
    username = request.POST["username"]
    password = request.POST["password"]
    user = authenticate(username, password)
    if user:
        request.session["user_id"] = user.id
        return redirect("/dashboard")
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-001")
}

func TestSESS001_Fixation_PHP(t *testing.T) {
	content := `function login($username, $password) {
    $user = checkCredentials($username, $password);
    if ($user) {
        $_SESSION['user'] = $user;
        header('Location: /dashboard');
    }
}
`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-001")
}

func TestSESS001_Fixation_JS(t *testing.T) {
	content := `app.post("/login", (req, res) => {
    const user = validateUser(req.body.username, req.body.password);
    if (user) {
        req.session.userId = user.id;
        res.redirect("/dashboard");
    }
});
`
	result := testutil.ScanContent(t, "/app/routes/auth.ts", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-001")
}

func TestSESS001_Safe_Regenerate_Python(t *testing.T) {
	content := `def login(request):
    user = authenticate(request.POST["username"], request.POST["password"])
    if user:
        request.session.cycle_key()
        request.session["user_id"] = user.id
        return redirect("/dashboard")
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-001")
}

func TestSESS001_Safe_Regenerate_PHP(t *testing.T) {
	content := `function login($username, $password) {
    $user = checkCredentials($username, $password);
    if ($user) {
        session_regenerate_id(true);
        $_SESSION['user'] = $user;
    }
}
`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-001")
}

// --- BATOU-SESS-002: Session cookie without HttpOnly flag ---

func TestSESS002_HttpOnlyFalse_JS(t *testing.T) {
	content := `const sessionOpts = { httpOnly: false, secure: true };`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-002")
}

func TestSESS002_HttpOnlyFalse_Python(t *testing.T) {
	content := `SESSION_COOKIE_HTTPONLY = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-002")
}

func TestSESS002_HttpOnlyFalse_PHP(t *testing.T) {
	content := `session.cookie_httponly = 0`
	result := testutil.ScanContent(t, "/app/config.php", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-002")
}

func TestSESS002_Safe_HttpOnlyTrue(t *testing.T) {
	content := `const sessionOpts = { httpOnly: true, secure: true };`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-002")
}

// --- BATOU-SESS-003: Session cookie without Secure flag ---

func TestSESS003_SecureFalse_JS(t *testing.T) {
	content := `const sessionOpts = { secure: false, httpOnly: true };`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-003")
}

func TestSESS003_SecureFalse_Python(t *testing.T) {
	content := `SESSION_COOKIE_SECURE = False`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-003")
}

func TestSESS003_SecureFalse_PHP(t *testing.T) {
	content := `session.cookie_secure = off`
	result := testutil.ScanContent(t, "/app/config.php", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-003")
}

func TestSESS003_Safe_SecureTrue(t *testing.T) {
	content := `const sessionOpts = { secure: true, httpOnly: true };`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-003")
}

// --- BATOU-SESS-004: Session cookie SameSite=None ---

func TestSESS004_SameSiteNone(t *testing.T) {
	content := `const sessionOpts = { sameSite: "none", secure: true };`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-004")
}

func TestSESS004_SameSiteNone_Python(t *testing.T) {
	content := `SESSION_COOKIE_SAMESITE = "None"`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-004")
}

func TestSESS004_Safe_SameSiteLax(t *testing.T) {
	content := `const sessionOpts = { sameSite: "lax" };`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-004")
}

// --- BATOU-SESS-005: Session data in localStorage ---

func TestSESS005_LocalStorage_SessionId(t *testing.T) {
	content := `localStorage.setItem("sessionId", response.sid);`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-005")
}

func TestSESS005_SessionStorage(t *testing.T) {
	content := `sessionStorage.setItem("token", authToken);`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-005")
}

func TestSESS005_Safe_Cookie(t *testing.T) {
	content := `document.cookie = "session=abc; HttpOnly; Secure";`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-005")
}

// --- BATOU-SESS-006: Session ID in URL ---

func TestSESS006_SessionInURL(t *testing.T) {
	content := `const link = "/dashboard?sessionId=abc123";`
	result := testutil.ScanContent(t, "/app/nav.js", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-006")
}

func TestSESS006_SessionURLParam(t *testing.T) {
	content := `const sid = req.query["PHPSESSID"];`
	result := testutil.ScanContent(t, "/app/routes/auth.ts", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-006")
}

func TestSESS006_Safe_NoSessionInURL(t *testing.T) {
	content := `const link = "/dashboard?page=1";`
	result := testutil.ScanContent(t, "/app/nav.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-006")
}

// --- BATOU-SESS-009: Predictable session ID generation ---

func TestSESS009_PredictableMD5(t *testing.T) {
	content := `session_id = md5(username)`
	result := testutil.ScanContent(t, "/app/session.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-009")
}

func TestSESS009_PredictableTimestamp(t *testing.T) {
	content := `sessionId = str(time.time())`
	result := testutil.ScanContent(t, "/app/session.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-009")
}

func TestSESS009_PredictableRandom(t *testing.T) {
	content := `session_id = str(random.randint(1000, 9999))`
	result := testutil.ScanContent(t, "/app/session.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-009")
}

func TestSESS009_Safe_SecureRandom(t *testing.T) {
	content := `session_id = secrets.token_hex(32)`
	result := testutil.ScanContent(t, "/app/session.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-009")
}

// --- BATOU-SESS-010: Sensitive data in session cookie ---

func TestSESS010_PasswordInSession(t *testing.T) {
	content := `request.session["password"] = user_password`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-010")
}

func TestSESS010_CreditCardInCookie(t *testing.T) {
	content := `response.set_cookie("credit_card", card_number)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-SESS-010")
}

func TestSESS010_Safe_UserIdOnly(t *testing.T) {
	content := `request.session["user_id"] = user.id`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-SESS-010")
}
