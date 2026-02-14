package auth

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// --- GTSS-AUTH-001: Hardcoded Credential Check ---

func TestAUTH001_Go_PasswordEquals(t *testing.T) {
	content := `if password == "admin123" { allow() }`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-001")
}

func TestAUTH001_Python_PasswordEquals(t *testing.T) {
	content := `if password == 'secret': grant_access()`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-001")
}

func TestAUTH001_JS_PasswordEquals(t *testing.T) {
	content := `if (password === "letmein") { return true; }`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-001")
}

func TestAUTH001_PHP_PasswordEquals(t *testing.T) {
	content := `<?php if ($password == "admin") { login(); } ?>`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-001")
}

func TestAUTH001_UsernameCheck(t *testing.T) {
	content := `if (username === "admin") { grantAdmin(); }`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-001")
}

// --- GTSS-AUTH-002: Missing Auth Check ---

func TestAUTH002_Go_AdminNoAuth(t *testing.T) {
	content := `package main
import "net/http"
func main() {
	http.HandleFunc("/admin/users", handleAdminUsers)
}`
	result := testutil.ScanContent(t, "/app/server.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-002")
}

func TestAUTH002_Express_AdminRoute(t *testing.T) {
	content := `app.get('/admin/dashboard', (req, res) => {
	res.render('dashboard');
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-002")
}

func TestAUTH002_Safe_WithAuthMiddleware(t *testing.T) {
	content := `const { authenticate } = require('./middleware');
app.get('/admin/dashboard', authenticate, (req, res) => {
	res.render('dashboard');
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-002")
}

func TestAUTH002_Django_NoDecorator(t *testing.T) {
	content := `def admin_dashboard(request):
    return render(request, 'dashboard.html')`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-002")
}

func TestAUTH002_Django_Safe_WithDecorator(t *testing.T) {
	content := `@login_required
def admin_dashboard(request):
    return render(request, 'dashboard.html')`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-002")
}

// --- GTSS-AUTH-003: CORS Wildcard ---

func TestAUTH003_CORSWildcard_Go(t *testing.T) {
	content := `w.Header().Set("Access-Control-Allow-Origin", "*")`
	result := testutil.ScanContent(t, "/app/middleware.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-003")
}

func TestAUTH003_CORSWildcard_JS(t *testing.T) {
	content := `app.use(cors({ origin: '*' }));`
	result := testutil.ScanContent(t, "/app/app.ts", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-003")
}

func TestAUTH003_CORSWildcard_Python(t *testing.T) {
	content := `CORS_ALLOW_ALL_ORIGINS = True`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-003")
}

func TestAUTH003_CORSAllOrigins_Go(t *testing.T) {
	content := `AllowAllOrigins: true`
	result := testutil.ScanContent(t, "/app/middleware.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-003")
}

// --- GTSS-AUTH-004: Session Fixation ---

func TestAUTH004_Python_LoginNoRegen(t *testing.T) {
	content := `def login(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(username, password)
    if user:
        request.session['user_id'] = user.id
        return redirect('/dashboard')`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-004")
}

func TestAUTH004_Python_Safe_WithCycleKey(t *testing.T) {
	content := `def login(request):
    username = request.POST['username']
    user = authenticate(username, request.POST['password'])
    if user:
        request.session.cycle_key()
        request.session['user_id'] = user.id
        return redirect('/dashboard')`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-004")
}

func TestAUTH004_PHP_LoginNoRegen(t *testing.T) {
	content := `<?php
function login($user, $pass) {
    if (check_password($user, $pass)) {
        $_SESSION['user'] = $user;
    }
}`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-004")
}

func TestAUTH004_Express_LoginNoRegen(t *testing.T) {
	content := `app.post('/login', (req, res) => {
	const { username, password } = req.body;
	if (checkCredentials(username, password)) {
		req.session.user = username;
		res.redirect('/dashboard');
	}
});`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-004")
}

// --- GTSS-AUTH-005: Weak Password Policy ---

func TestAUTH005_ShortMinLength(t *testing.T) {
	content := `if len(password) >= 4 { accept() }`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-005")
}

func TestAUTH005_MinLenConfig(t *testing.T) {
	content := `MIN_PASSWORD_LENGTH = 6`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-005")
}

func TestAUTH005_Safe_GoodLength(t *testing.T) {
	content := `if len(password) >= 8 { accept() }`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-005")
}

// --- GTSS-AUTH-006: Insecure Cookie ---

func TestAUTH006_Go_CookieNoSecure(t *testing.T) {
	content := `cookie := &http.Cookie{
	Name:  "session",
	Value: sessionID,
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-006")
}

func TestAUTH006_Go_Safe_WithFlags(t *testing.T) {
	content := `cookie := &http.Cookie{
	Name:     "session",
	Value:    sessionID,
	Secure:   true,
	HttpOnly: true,
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-006")
}

func TestAUTH006_JS_CookieNoSecure(t *testing.T) {
	content := `res.cookie('session', token, {
	maxAge: 3600000
});`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-006")
}

func TestAUTH006_PHP_SetcookieInsecure(t *testing.T) {
	content := `<?php setcookie("session", $sid, time()+3600, "/"); ?>`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-006")
}

// --- GTSS-AUTH-007: Privilege Escalation ---

func TestAUTH007_C_Setuid0(t *testing.T) {
	content := `#include <unistd.h>
int main() {
    setuid(0);
    execl("/bin/sh", "sh", NULL);
}`
	result := testutil.ScanContent(t, "/app/escalate.c", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_C_Setgid0(t *testing.T) {
	content := `#include <unistd.h>
void setup() {
    setgid(0);
}`
	result := testutil.ScanContent(t, "/app/setup.c", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Python_Setuid0(t *testing.T) {
	content := `import os
os.setuid(0)
os.system("whoami")`
	result := testutil.ScanContent(t, "/app/escalate.py", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Chmod777(t *testing.T) {
	content := `chmod 777 /var/data/uploads`
	result := testutil.ScanContent(t, "/app/setup.sh", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_ChmodARWX(t *testing.T) {
	content := `chmod a+rwx /tmp/data`
	result := testutil.ScanContent(t, "/app/deploy.sh", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Go_OsChmod777(t *testing.T) {
	content := `package main
import "os"
func setup() {
	os.Chmod("/var/data", 0777)
}`
	result := testutil.ScanContent(t, "/app/setup.go", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Dockerfile_UserRoot(t *testing.T) {
	content := `FROM ubuntu:20.04
RUN apt-get update
USER root
CMD ["./app"]`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Safe_Dockerfile_UserNonroot(t *testing.T) {
	content := `FROM ubuntu:20.04
USER root
RUN apt-get update && apt-get install -y curl
USER appuser
CMD ["./app"]`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Safe_Chmod644(t *testing.T) {
	content := `chmod 644 /var/data/config.yml`
	result := testutil.ScanContent(t, "/app/setup.sh", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-007")
}

func TestAUTH007_Safe_Go_Chmod755(t *testing.T) {
	content := `package main
import "os"
func setup() {
	os.Chmod("/var/data", 0755)
}`
	result := testutil.ScanContent(t, "/app/setup.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-AUTH-007")
}
