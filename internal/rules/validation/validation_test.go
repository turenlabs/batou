package validation

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
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

// --- GTSS-VAL-005: File Upload Hardening ---

func TestVAL005_Go_FormFileNoContentCheck(t *testing.T) {
	content := `package main
import "net/http"
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("upload")
	if err != nil { return }
	defer file.Close()
	dst, _ := os.Create("/uploads/" + header.Filename)
	io.Copy(dst, file)
}`
	result := testutil.ScanContent(t, "/app/upload.go", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_Python_FilesNoCheck(t *testing.T) {
	content := `def upload(request):
    f = request.FILES['document']
    with open('/uploads/' + f.name, 'wb') as dest:
        for chunk in f.chunks():
            dest.write(chunk)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_JS_MulterNoFilter(t *testing.T) {
	content := `const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('avatar'), (req, res) => {
	res.json({ path: req.file.path });
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_Java_MultipartNoCheck(t *testing.T) {
	content := `@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    file.transferTo(new File("/uploads/" + file.getOriginalFilename()));
    return "uploaded";
}`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_PHP_FilesNoCheck(t *testing.T) {
	content := `<?php
$target = "uploads/" . basename($_FILES["file"]["name"]);
move_uploaded_file($_FILES["file"]["tmp_name"], $target);
echo "Uploaded";`
	result := testutil.ScanContent(t, "/app/upload.php", content)
	testutil.MustFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_WebAccessibleDir(t *testing.T) {
	content := `const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
	const dest = 'public/uploads/' + req.file.originalname;
	fs.renameSync(req.file.path, dest);
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	// Should find both content-type and web-accessible dir issues
	testutil.MustFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_Safe_Go_WithDetectContentType(t *testing.T) {
	content := `package main
import "net/http"
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("upload")
	if err != nil { return }
	defer file.Close()
	buf := make([]byte, 512)
	file.Read(buf)
	contentType := http.DetectContentType(buf)
	if contentType != "image/jpeg" && contentType != "image/png" {
		http.Error(w, "invalid file type", 400)
		return
	}
}`
	result := testutil.ScanContent(t, "/app/upload.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_Safe_JS_WithFileFilter(t *testing.T) {
	content := `const upload = multer({
	dest: 'uploads/',
	fileFilter: (req, file, cb) => {
		if (!allowedTypes.includes(file.mimetype)) {
			return cb(new Error('Invalid type'));
		}
		cb(null, true);
	}
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-005")
}

func TestVAL005_Safe_Python_WithContentCheck(t *testing.T) {
	content := `def upload(request):
    f = request.FILES['document']
    if f.content_type not in ALLOWED_EXTENSIONS:
        return HttpResponseBadRequest("Invalid file type")
    save_file(f)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-VAL-005")
}
