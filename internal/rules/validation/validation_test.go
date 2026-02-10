package validation

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// --- GTSS-VAL-001: Direct Request Parameter Usage ---

func TestVAL001_Flask_RequestArgs(t *testing.T) {
	content := `name = request.args.get('name')
db.execute("SELECT * FROM users WHERE name = '" + name + "'")`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Django_RequestData(t *testing.T) {
	content := `user_id = request.GET['id']
return User.objects.get(id=user_id)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Express_Params(t *testing.T) {
	content := `const name = req.query.name;
db.query("SELECT * FROM users WHERE name = " + name);`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Go_FormValue(t *testing.T) {
	content := `name := r.FormValue("name")
db.Exec("DELETE FROM users WHERE name = '" + name + "'")`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Java_GetParameter(t *testing.T) {
	content := `String id = request.getParameter("id");
stmt.execute("DELETE FROM users WHERE id = " + id);`
	result := testutil.ScanContent(t, "/app/Servlet.java", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_PHP_Superglobal(t *testing.T) {
	content := `<?php
$name = $_GET['name'];
$query = "SELECT * FROM users WHERE name = '$name'";`
	result := testutil.ScanContent(t, "/app/search.php", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Ruby_Params(t *testing.T) {
	content := `name = params[:name]
User.where("name = '#{name}'")`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Safe_WithValidation(t *testing.T) {
	content := `const name = req.query.name;
const sanitized = sanitize(name);
db.query("SELECT * FROM users WHERE name = ?", sanitized);`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-001")
}

func TestVAL001_Fixture_MissingValidation_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/missing_validation.ts")
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	hasVAL := testutil.HasFinding(result, "GTSS-VAL-001") ||
		testutil.HasFinding(result, "GTSS-VAL-002") ||
		testutil.HasFinding(result, "GTSS-VAL-003")
	if !hasVAL {
		t.Errorf("expected validation finding in missing_validation.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-VAL-002: Missing Type Coercion ---

func TestVAL002_ParseIntNoCheck(t *testing.T) {
	content := `const id = parseInt(req.params.id);
const user = await db.findOne({ id });`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-002")
}

func TestVAL002_Safe_WithNaNCheck(t *testing.T) {
	content := `const id = parseInt(req.params.id);
if (isNaN(id)) return res.status(400).send('Invalid ID');
const user = await db.findOne({ id });`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-002")
}

func TestVAL002_ArrayUserIndex(t *testing.T) {
	content := `const item = items[req.query.index];`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-002")
}

// --- GTSS-VAL-003: Missing Length Validation ---

func TestVAL003_FileUploadNoLimit(t *testing.T) {
	content := `const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), handler);`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-003")
}

func TestVAL003_Safe_WithFileLimit(t *testing.T) {
	content := `const upload = multer({ dest: 'uploads/', limits: { fileSize: 5242880 } });
app.post('/upload', upload.single('file'), handler);`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-003")
}

func TestVAL003_DBOpNoLengthCheck(t *testing.T) {
	content := `const name = req.body.name;
const bio = req.body.bio;
await User.create({ name, bio });`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-003")
}

// --- GTSS-VAL-004: Missing Allowlist Validation ---

func TestVAL004_JS_DynPropAccess(t *testing.T) {
	content := `const field = req.query.field;
const value = data[req.query.key];`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-004")
}

func TestVAL004_Python_DynAttr(t *testing.T) {
	content := `field = request.args.get('field')
value = getattr(obj, request.args.get('attr'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-004")
}

func TestVAL004_Go_DynMapAccess(t *testing.T) {
	content := `key := r.URL.Query().Get("key")
value := config[r.FormValue("field")]`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-004")
}

func TestVAL004_Safe_WithAllowlist(t *testing.T) {
	content := `const allowed = ['name', 'email', 'bio'];
const field = req.query.field;
if (!allowed.includes(field)) return;
const value = data[req.query.field];`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-004")
}
