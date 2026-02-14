package python

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-PY-001: Subprocess Shell Injection
// ==========================================================================

func TestPY001_SubprocessShellTrue(t *testing.T) {
	content := `import subprocess
def run_cmd(user_input):
    subprocess.Popen(user_input, shell=True)
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-001")
}

func TestPY001_SubprocessCallShellTrue(t *testing.T) {
	content := `import subprocess
def execute(cmd):
    subprocess.call(cmd, shell=True)
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-001")
}

func TestPY001_SubprocessFString(t *testing.T) {
	content := `import subprocess
def run_cmd(user_input):
    subprocess.run(f"echo {user_input}", shell=True)
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-001")
}

func TestPY001_SubprocessFormat(t *testing.T) {
	content := `import subprocess
def run_cmd(user_input):
    subprocess.check_output("echo {}".format(user_input), shell=True)
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-001")
}

func TestPY001_SubprocessList_Safe(t *testing.T) {
	content := `import subprocess
def run_cmd(user_input):
    subprocess.run(["echo", user_input])
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-001")
}

// ==========================================================================
// GTSS-PY-002: Path Traversal via os.path.join
// ==========================================================================

func TestPY002_OsPathJoin_WithRequest(t *testing.T) {
	content := `import os
from flask import request
def download():
    filename = request.args.get("file")
    path = os.path.join("/uploads", filename)
    return send_file(path)
`
	result := testutil.ScanContent(t, "/app/download.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-002")
}

func TestPY002_OsPathJoin_NoUserInput_Safe(t *testing.T) {
	content := `import os
def get_config():
    path = os.path.join("/etc", "app", "config.yaml")
    return open(path).read()
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-002")
}

// ==========================================================================
// GTSS-PY-003: Jinja2 Autoescape Disabled
// ==========================================================================

func TestPY003_Jinja2_AutoescapeFalse(t *testing.T) {
	content := `from jinja2 import Environment
env = Environment(autoescape=False, loader=FileSystemLoader("templates"))
`
	result := testutil.ScanContent(t, "/app/templates.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-003")
}

func TestPY003_Jinja2_AutoescapeTrue_Safe(t *testing.T) {
	content := `from jinja2 import Environment, select_autoescape
env = Environment(autoescape=select_autoescape(['html', 'xml']), loader=FileSystemLoader("templates"))
`
	result := testutil.ScanContent(t, "/app/templates.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-003")
}

// ==========================================================================
// GTSS-PY-004: Unsafe YAML Load
// ==========================================================================

func TestPY004_YamlLoad_NoSafeLoader(t *testing.T) {
	content := `import yaml
def parse_config(data):
    return yaml.load(data)
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-004")
}

func TestPY004_YamlUnsafeLoad(t *testing.T) {
	content := `import yaml
def parse_data(raw):
    return yaml.unsafe_load(raw)
`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-004")
}

func TestPY004_YamlLoad_SafeLoader_Safe(t *testing.T) {
	content := `import yaml
def parse_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-004")
}

func TestPY004_YamlSafeLoad_Safe(t *testing.T) {
	content := `import yaml
def parse_config(data):
    return yaml.safe_load(data)
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-004")
}

// ==========================================================================
// GTSS-PY-005: tempfile.mktemp Race Condition
// ==========================================================================

func TestPY005_TempfileMktemp(t *testing.T) {
	content := `import tempfile
def create_temp():
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write("data")
`
	result := testutil.ScanContent(t, "/app/temp.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-005")
}

func TestPY005_TempfileMkstemp_Safe(t *testing.T) {
	content := `import tempfile
def create_temp():
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("data")
`
	result := testutil.ScanContent(t, "/app/temp.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-005")
}

func TestPY005_NamedTemporaryFile_Safe(t *testing.T) {
	content := `import tempfile
def create_temp():
    with tempfile.NamedTemporaryFile(suffix=".txt") as f:
        f.write(b"data")
`
	result := testutil.ScanContent(t, "/app/temp.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-005")
}

// ==========================================================================
// GTSS-PY-006: Assert for Security Checks
// ==========================================================================

func TestPY006_AssertIsAuthenticated(t *testing.T) {
	content := `def protected_view(request):
    assert request.user.is_authenticated
    return render(request, "secret.html")
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-006")
}

func TestPY006_AssertIsAdmin(t *testing.T) {
	content := `def admin_view(request):
    assert request.user.is_admin
    return delete_all_records()
`
	result := testutil.ScanContent(t, "/app/admin.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-006")
}

func TestPY006_AssertHasPermission(t *testing.T) {
	content := `def edit_post(request, post_id):
    assert user.has_permission("edit")
    post.save()
`
	result := testutil.ScanContent(t, "/app/posts.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-006")
}

func TestPY006_IfCheck_Safe(t *testing.T) {
	content := `def protected_view(request):
    if not request.user.is_authenticated:
        raise PermissionError("Not authenticated")
    return render(request, "secret.html")
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-006")
}

// ==========================================================================
// GTSS-PY-007: Unsafe Deserialization
// ==========================================================================

func TestPY007_PickleLoad_WithRequest(t *testing.T) {
	content := `import pickle
from flask import request
def handle():
    data = request.get_data()
    obj = pickle.loads(data)
`
	result := testutil.ScanContent(t, "/app/handler.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-007")
}

func TestPY007_DillLoad_WithSocket(t *testing.T) {
	content := `import dill
import socket
def receive(conn):
    data = conn.recv(4096)
    obj = dill.loads(data)
`
	result := testutil.ScanContent(t, "/app/server.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-007")
}

func TestPY007_PickleLoad_InternalFile_Safe(t *testing.T) {
	content := `import pickle
def load_model():
    with open("model.pkl", "rb") as f:
        return pickle.load(f)
`
	result := testutil.ScanContent(t, "/app/model.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-007")
}

// ==========================================================================
// GTSS-PY-008: Timing Attack on Secret Comparison
// ==========================================================================

func TestPY008_DirectTokenCompare(t *testing.T) {
	content := `def verify_api_key(request):
    api_key = request.headers.get("X-API-Key")
    if api_key == EXPECTED_KEY:
        return True
`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-008")
}

func TestPY008_DirectTokenCompare_NotEqual(t *testing.T) {
	content := `def verify_token(request):
    token = request.headers.get("Authorization")
    if token != expected_token:
        raise Unauthorized()
`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-008")
}

func TestPY008_HmacCompareDigest_Safe(t *testing.T) {
	content := `import hmac
def verify_api_key(provided, expected):
    if hmac.compare_digest(provided, expected):
        return True
`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-008")
}

// ==========================================================================
// GTSS-PY-009: Django Raw SQL Injection
// ==========================================================================

func TestPY009_DjangoRaw_FString(t *testing.T) {
	content := `def search_users(name):
    return User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-009")
}

func TestPY009_DjangoRaw_PercentFormat(t *testing.T) {
	content := `def search_users(name):
    return User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-009")
}

func TestPY009_DjangoExtra(t *testing.T) {
	content := `def filter_users(search):
    return User.objects.extra(where=["name LIKE '%%%s%%'" % search])
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-009")
}

func TestPY009_DjangoRaw_Parameterized_Safe(t *testing.T) {
	content := `def search_users(name):
    return User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-009")
}

// ==========================================================================
// GTSS-PY-010: Flask Hardcoded Secret Key
// ==========================================================================

func TestPY010_FlaskSecretHardcoded(t *testing.T) {
	content := `from flask import Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-12345'
`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-010")
}

func TestPY010_DjangoSecretHardcoded(t *testing.T) {
	content := `SECRET_KEY = 'django-insecure-abc123xyz789'
`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-010")
}

func TestPY010_SecretFromEnv_Safe(t *testing.T) {
	content := `import os
SECRET_KEY = os.environ['SECRET_KEY']
`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-010")
}

func TestPY010_SecretGetenv_Safe(t *testing.T) {
	content := `import os
SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-only-for-dev')
`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-010")
}

// ==========================================================================
// GTSS-PY-011: TLS Verification Disabled
// ==========================================================================

func TestPY011_RequestsVerifyFalse(t *testing.T) {
	content := `import requests
def fetch(url):
    return requests.get(url, verify=False)
`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-011")
}

func TestPY011_HttpxVerifyFalse(t *testing.T) {
	content := `import httpx
client = httpx.Client(verify=False)
`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-011")
}

func TestPY011_Urllib3DisableWarnings(t *testing.T) {
	content := `import urllib3
urllib3.disable_warnings()
`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-011")
}

func TestPY011_SslUnverifiedContext(t *testing.T) {
	content := `import ssl
ctx = ssl._create_unverified_context()
`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-011")
}

func TestPY011_RequestsDefault_Safe(t *testing.T) {
	content := `import requests
def fetch(url):
    return requests.get(url)
`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-011")
}

// ==========================================================================
// GTSS-PY-012: ReDoS via User-Controlled Regex
// ==========================================================================

func TestPY012_ReCompile_UserInput(t *testing.T) {
	content := `import re
from flask import request
def search(request):
    pattern = request.args.get("pattern")
    results = re.findall(pattern, text)
`
	result := testutil.ScanContent(t, "/app/search.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-012")
}

func TestPY012_ReCompile_WithEscape_Safe(t *testing.T) {
	content := `import re
from flask import request
def search(request):
    pattern = request.args.get("q")
    results = re.findall(re.escape(pattern), text)
`
	result := testutil.ScanContent(t, "/app/search.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-012")
}

func TestPY012_ReCompile_StaticPattern_Safe(t *testing.T) {
	content := `import re
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
`
	result := testutil.ScanContent(t, "/app/validators.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-012")
}

// ==========================================================================
// GTSS-PY-013: Unsafe Archive Extraction
// ==========================================================================

func TestPY013_TarExtractAll_NoFilter(t *testing.T) {
	content := `import tarfile
def extract(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)
`
	result := testutil.ScanContent(t, "/app/extractor.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-013")
}

func TestPY013_TarExtractAll_WithFilter_Safe(t *testing.T) {
	content := `import tarfile
def extract(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest, filter='data')
`
	result := testutil.ScanContent(t, "/app/extractor.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-013")
}

func TestPY013_TarExtractAll_WithMembers_Safe(t *testing.T) {
	content := `import tarfile
def extract(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        safe_members = [m for m in tar.getmembers() if not m.name.startswith("..")]
        tar.extractall(dest, members=safe_members)
`
	result := testutil.ScanContent(t, "/app/extractor.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-013")
}

// ==========================================================================
// GTSS-PY-014: Logging with String Formatting
// ==========================================================================

func TestPY014_LoggingFString(t *testing.T) {
	content := `import logging
logger = logging.getLogger(__name__)
def handle(request):
    username = request.user.name
    logger.info(f"User {username} logged in")
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-014")
}

func TestPY014_LoggingDotFormat(t *testing.T) {
	content := `import logging
def handle(name):
    logging.error("Failed for user {}".format(name))
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-014")
}

func TestPY014_LoggingPercentFormat(t *testing.T) {
	content := `import logging
def handle(name):
    logging.warning("Failed for %s" % name)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-014")
}

func TestPY014_LoggingLazyFormat_Safe(t *testing.T) {
	content := `import logging
logger = logging.getLogger(__name__)
def handle(name):
    logger.info("User %s logged in", name)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-014")
}

// ==========================================================================
// GTSS-PY-015: JWT Decode Without Verification
// ==========================================================================

func TestPY015_JwtDecode_VerifyFalse(t *testing.T) {
	content := `import jwt
def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})
`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-015")
}

func TestPY015_JwtDecode_AlgorithmNone(t *testing.T) {
	content := `import jwt
def decode_token(token):
    return jwt.decode(token, algorithms=["none"])
`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-015")
}

func TestPY015_JwtDecode_Verified_Safe(t *testing.T) {
	content := `import jwt
def decode_token(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])
`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-015")
}

// ==========================================================================
// GTSS-PY-016: Debugger in Production
// ==========================================================================

func TestPY016_FlaskDebugTrue(t *testing.T) {
	content := `from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    app.run(debug=True)
`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-016")
}

func TestPY016_WerkzeugDebugger(t *testing.T) {
	content := `from werkzeug.serving import run_simple
run_simple("0.0.0.0", 5000, app, use_debugger=True)
`
	result := testutil.ScanContent(t, "/app/server.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-016")
}

func TestPY016_DebugToolbar(t *testing.T) {
	content := `from flask_debugtoolbar import DebugToolbarExtension
toolbar = DebugToolbarExtension(app)
`
	result := testutil.ScanContent(t, "/app/extensions.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-016")
}

func TestPY016_FlaskRun_NoDebug_Safe(t *testing.T) {
	content := `from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    app.run()
`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-016")
}

// ==========================================================================
// GTSS-PY-017: FastAPI Missing Input Validation
// ==========================================================================

func TestPY017_FastAPIQueryNoConstraints(t *testing.T) {
	content := `from fastapi import FastAPI, Query
app = FastAPI()

@app.get("/search")
def search(q: str = Query()):
    return {"results": db.search(q)}
`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-017")
}

func TestPY017_FastAPIRawBody(t *testing.T) {
	content := `from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/data")
async def handle(request: Request):
    data = await request.json()
    process(data)
`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-017")
}

func TestPY017_FastAPIQueryWithConstraints_Safe(t *testing.T) {
	content := `from fastapi import FastAPI, Query
app = FastAPI()

@app.get("/search")
def search(q: str = Query(min_length=1, max_length=100)):
    return {"results": db.search(q)}
`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-017")
}

// ==========================================================================
// GTSS-PY-018: Asyncio Subprocess Shell Injection
// ==========================================================================

func TestPY018_AsyncioCreateSubprocessShell(t *testing.T) {
	content := `import asyncio
async def run_command(cmd):
    proc = await asyncio.create_subprocess_shell(cmd)
    await proc.wait()
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-018")
}

func TestPY018_AsyncioCreateSubprocessShell_FString(t *testing.T) {
	content := `import asyncio
async def run_command(user_input):
    proc = await asyncio.create_subprocess_shell(f"echo {user_input}")
    await proc.wait()
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustFindRule(t, result, "GTSS-PY-018")
}

func TestPY018_AsyncioCreateSubprocessExec_Safe(t *testing.T) {
	content := `import asyncio
async def run_command(arg):
    proc = await asyncio.create_subprocess_exec("echo", arg)
    await proc.wait()
`
	result := testutil.ScanContent(t, "/app/runner.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-PY-018")
}
