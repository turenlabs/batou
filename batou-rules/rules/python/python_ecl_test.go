package python

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-PY-031: paramiko AutoAddPolicy / WarningPolicy (CWE-295)
// ==========================================================================

func TestPY031_ParamikoAutoAdd(t *testing.T) {
	content := `import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=u, password=p)
`
	result := testutil.ScanContent(t, "/app/ssh.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-031")
}

func TestPY031_ParamikoWarning(t *testing.T) {
	content := `import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.WarningPolicy())
`
	result := testutil.ScanContent(t, "/app/ssh.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-031")
}

func TestPY031_RejectPolicySafe(t *testing.T) {
	content := `import paramiko
client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
`
	result := testutil.ScanContent(t, "/app/ssh.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-031")
}

// ==========================================================================
// BATOU-PY-033: ssl.wrap_socket() / insecure protocol (CWE-326)
// ==========================================================================

func TestPY033_SSLWrapSocket(t *testing.T) {
	content := `import ssl, socket
s = socket.socket()
wrapped = ssl.wrap_socket(s)
`
	result := testutil.ScanContent(t, "/app/net.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-033")
}

func TestPY033_SSLInsecureProto(t *testing.T) {
	content := `import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
`
	result := testutil.ScanContent(t, "/app/net.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-033")
}

func TestPY033_SSLDefaultContextSafe(t *testing.T) {
	content := `import ssl
ctx = ssl.create_default_context()
wrapped = ctx.wrap_socket(sock, server_hostname=host)
`
	result := testutil.ScanContent(t, "/app/net.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-033")
}

func TestPY033_SSLProtocolTLSClientSafe(t *testing.T) {
	content := `import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
`
	result := testutil.ScanContent(t, "/app/net.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-033")
}

// ==========================================================================
// BATOU-PY-035: hashids seeded with SECRET_KEY (CWE-326)
// ==========================================================================

func TestPY035_HashidsSecretKey(t *testing.T) {
	content := `from hashids import Hashids
hasher = Hashids(salt=SECRET_KEY, min_length=8)
`
	result := testutil.ScanContent(t, "/app/ids.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-035")
}

func TestPY035_HashidsAppSecret(t *testing.T) {
	content := `from hashids import Hashids
hasher = Hashids(app.secret_key)
`
	result := testutil.ScanContent(t, "/app/ids.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-035")
}

func TestPY035_HashidsRandomSaltSafe(t *testing.T) {
	content := `from hashids import Hashids
hasher = Hashids(salt="this-is-a-dedicated-hashids-salt", min_length=8)
`
	result := testutil.ScanContent(t, "/app/ids.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-035")
}

// ==========================================================================
// BATOU-PY-037: render context built from globals()/locals() (CWE-200)
// ==========================================================================

func TestPY037_RenderLocals(t *testing.T) {
	content := `from django.shortcuts import render
def view(request):
    user = request.user
    secret = settings.SECRET_KEY
    return render(request, "page.html", locals())
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-037")
}

func TestPY037_ContextGlobals(t *testing.T) {
	content := `from django.template import Context
ctx = Context(globals())
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-037")
}

func TestPY037_ExplicitContextSafe(t *testing.T) {
	content := `from django.shortcuts import render
def view(request):
    return render(request, "page.html", {"user": request.user, "items": items})
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-037")
}

// ==========================================================================
// BATOU-PY-040: float(user_input) NaN injection (CWE-1289)
// ==========================================================================

func TestPY040_FloatRequestArgs(t *testing.T) {
	content := `from flask import request
def buy():
    amount = float(request.args["amount"])
    if amount < MAX_AMOUNT:
        charge(amount)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-040")
}

func TestPY040_FloatRequestForm(t *testing.T) {
	content := `from flask import request
def update():
    qty = float(request.form.get("qty"))
    return qty
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-040")
}

func TestPY040_FloatConstantSafe(t *testing.T) {
	content := `PI = float("3.14159")
ratio = float(numerator) / float(denominator)
`
	result := testutil.ScanContent(t, "/app/math.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-040")
}

func TestPY040_FloatValidatedSafe(t *testing.T) {
	// Conversion of a non-request variable — the rule only anchors on direct
	// request data, so an already-extracted/validated var stays clean.
	content := `def compute(raw_value):
    v = float(raw_value)
    return v
`
	result := testutil.ScanContent(t, "/app/calc.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-040")
}

// ==========================================================================
// BATOU-PY-041: os.open/mkdir/makedirs world-writable mode (CWE-732)
// ==========================================================================

func TestPY041_OsOpenWorldWritable(t *testing.T) {
	content := `import os
fd = os.open("/var/run/app.sock", os.O_CREAT | os.O_WRONLY, 0o777)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-041")
}

func TestPY041_OsMakedirsWorldWritable(t *testing.T) {
	content := `import os
os.makedirs("/srv/uploads", 0o777)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-041")
}

func TestPY041_OsMkdir666(t *testing.T) {
	content := `import os
os.mkdir("/tmp/shared", 0o666)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-041")
}

func TestPY041_OsUmaskZero(t *testing.T) {
	content := `import os
os.umask(0)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustFindRule(t, result, "BATOU-PY-041")
}

func TestPY041_OsMkdirRestrictiveSafe(t *testing.T) {
	// 0o755 / 0o700 / 0o600 are the safe, intended modes — must NOT fire.
	content := `import os
os.makedirs("/srv/uploads", 0o755)
os.mkdir("/srv/private", 0o700)
fd = os.open("/srv/secret", os.O_CREAT | os.O_WRONLY, 0o600)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-041")
}

func TestPY041_OsChmodNotDoubleCounted(t *testing.T) {
	// os.chmod is BATOU-PY-022's job, not PY-041 — PY-041 must not fire on it.
	content := `import os
os.chmod("/etc/app.conf", 0o777)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-041")
}

func TestPY041_UmaskRestrictiveSafe(t *testing.T) {
	// os.umask(0o077) is the secure form — only umask(0)/umask(0o000) fire.
	content := `import os
os.umask(0o077)
`
	result := testutil.ScanContent(t, "/app/srv.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-PY-041")
}
