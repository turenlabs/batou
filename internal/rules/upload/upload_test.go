package upload

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-UPLOAD-001: File upload without type validation ---

func TestUPLOAD001_NoValidation_Python(t *testing.T) {
	content := `request.files["avatar"].save("/uploads/" + uploaded.filename)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-001")
}

func TestUPLOAD001_NoValidation_PHP(t *testing.T) {
	content := `move_uploaded_file($_FILES["file"]["tmp_name"], "/uploads/" . $_FILES["file"]["name"]);`
	result := testutil.ScanContent(t, "/app/upload.php", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-001")
}

func TestUPLOAD001_NoValidation_Java(t *testing.T) {
	content := `MultipartFile file = request.getFile(); file.transferTo(new File("/uploads/" + file.getOriginalFilename()));`
	result := testutil.ScanContent(t, "/app/Upload.java", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-001")
}

func TestUPLOAD001_NoValidation_Go(t *testing.T) {
	content := `file, header, _ := r.FormFile("upload")
dst, _ := os.Create("/uploads/" + header.Filename)
io.Copy(dst, file)
`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-001")
}

func TestUPLOAD001_Safe_WithTypeCheck(t *testing.T) {
	content := `uploaded = request.files["avatar"]
if uploaded.content_type not in ALLOWED_EXTENSIONS:
    abort(400)
uploaded.save("/uploads/" + secure_filename(uploaded.filename))
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-UPLOAD-001")
}

// --- BATOU-UPLOAD-002: File upload path traversal ---

func TestUPLOAD002_PathTraversal_Python(t *testing.T) {
	content := `path = os.path.join(upload_dir, request.files["file"].filename)
open(path, "wb").write(data)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-002")
}

func TestUPLOAD002_PathTraversal_JS(t *testing.T) {
	content := `const dest = path.join(uploadDir, req.files.file.originalname);
fs.writeFileSync(dest, data);
`
	result := testutil.ScanContent(t, "/app/upload.js", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-002")
}

func TestUPLOAD002_PathTraversal_Go(t *testing.T) {
	content := `dest := filepath.Join(uploadDir, filename)
os.Create(dest)
`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-002")
}

func TestUPLOAD002_Safe_SecureFilename(t *testing.T) {
	content := `safe = secure_filename(request.files["file"].filename)
path = os.path.join(upload_dir, safe)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-UPLOAD-002")
}

// --- BATOU-UPLOAD-003: Upload to publicly accessible directory ---

func TestUPLOAD003_PublicDir_Python(t *testing.T) {
	content := `upload_dir = "static/uploads/"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-003")
}

func TestUPLOAD003_PublicDir_JS(t *testing.T) {
	content := `const dest = path.join("public/uploads", filename);`
	result := testutil.ScanContent(t, "/app/upload.js", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-003")
}

func TestUPLOAD003_Safe_PrivateDir(t *testing.T) {
	content := `save_path = "/var/app/data/incoming/"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-UPLOAD-003")
}

// --- BATOU-UPLOAD-004: File upload without size limit ---

func TestUPLOAD004_NoSize_Python(t *testing.T) {
	content := `MAX_CONTENT_LENGTH = None`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-004")
}

func TestUPLOAD004_NoSize_Java(t *testing.T) {
	content := `factory.setMaxFileSize(-1);`
	result := testutil.ScanContent(t, "/app/Config.java", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-004")
}

func TestUPLOAD004_Safe_WithLimit(t *testing.T) {
	content := `MAX_CONTENT_LENGTH = 16 * 1024 * 1024`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-UPLOAD-004")
}

// --- BATOU-UPLOAD-006: Executable file extension allowed ---

func TestUPLOAD006_ExecutableExt(t *testing.T) {
	content := `allowed_extensions = [".jpg", ".png", ".php", ".gif"]`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-006")
}

func TestUPLOAD006_ExecutableExt_JSP(t *testing.T) {
	content := `allowed_types = [".pdf", ".jsp", ".doc"]`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-006")
}

func TestUPLOAD006_Safe_OnlyImages(t *testing.T) {
	content := `allowed_extensions = [".jpg", ".png", ".gif", ".webp"]`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-UPLOAD-006")
}

// --- BATOU-UPLOAD-007: SVG upload without sanitization ---

func TestUPLOAD007_SVG_NoSanitize(t *testing.T) {
	content := `allowed_extensions = [".jpg", ".png", ".svg"]`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-007")
}

func TestUPLOAD007_SVG_MimeCheck(t *testing.T) {
	content := `if content_type == "image/svg+xml":
    save_file(f)
`
	result := testutil.ScanContent(t, "/app/upload.py", content)
	testutil.MustFindRule(t, result, "BATOU-UPLOAD-007")
}

func TestUPLOAD007_Safe_SVG_WithSanitize(t *testing.T) {
	content := `allowed_mimes = [".svg"]
sanitize_svg(uploaded_content)
`
	result := testutil.ScanContent(t, "/app/upload.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-UPLOAD-007")
}
