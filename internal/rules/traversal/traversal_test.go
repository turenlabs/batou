package traversal

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-TRV-001: Path Traversal ---

func TestTRV001_PathTraversal_Go_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/path_traversal.go")
	result := testutil.ScanContent(t, "/app/handlers/file.go", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_PathTraversal_JS_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/path_traversal.ts")
	result := testutil.ScanContent(t, "/app/routes/file.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_PathTraversal_Python_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/path_traversal.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_PathTraversal_PHP_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/path_traversal.php")
	result := testutil.ScanContent(t, "/app/download.php", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_PathTraversal_Ruby_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "ruby/vulnerable/path_traversal.rb")
	result := testutil.ScanContent(t, "/app/file.rb", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_PathTraversal_Java_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/PathTraversal.java")
	result := testutil.ScanContent(t, "/app/FileServlet.java", content)
	hasTRV := testutil.HasFinding(result, "GTSS-TRV-001") || testutil.HasFinding(result, "GTSS-TRV-002")
	if !hasTRV {
		t.Errorf("expected traversal finding in PathTraversal.java, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestTRV001_PathTraversal_C_Fixture(t *testing.T) {
	if !testutil.FixtureExists("c/vulnerable/path_traversal.c") {
		t.Skip("C fixture not available")
	}
	content := testutil.LoadFixture(t, "c/vulnerable/path_traversal.c")
	result := testutil.ScanContent(t, "/app/file.c", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_Safe_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/safe/path_safe.go")
	result := testutil.ScanContent(t, "/app/handlers/file.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_Safe_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/path_safe.ts")
	result := testutil.ScanContent(t, "/app/routes/file.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_Safe_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/path_safe.py")
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-001")
}

func TestTRV001_Safe_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/safe/PathSafe.java")
	result := testutil.ScanContent(t, "/app/FileServlet.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-001")
}

// --- GTSS-TRV-002: File Inclusion ---

func TestTRV002_FileInclusion_PHP_Local(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/file_inclusion_local.php")
	result := testutil.ScanContent(t, "/app/include.php", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-002")
}

func TestTRV002_FileInclusion_PHP_Remote(t *testing.T) {
	content := testutil.LoadFixture(t, "php/vulnerable/file_inclusion_remote.php")
	result := testutil.ScanContent(t, "/app/include.php", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-002")
}

func TestTRV002_FileInclusion_PHP_Inline(t *testing.T) {
	content := `<?php include($page); ?>`
	result := testutil.ScanContent(t, "/app/include.php", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-002")
}

func TestTRV002_FileInclusion_Python_Dynamic(t *testing.T) {
	content := `module_name = request.args.get('module')
mod = __import__(module_name)`
	result := testutil.ScanContent(t, "/app/loader.py", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-002")
}

func TestTRV002_Safe_PHP(t *testing.T) {
	content := testutil.LoadFixture(t, "php/safe/file_safe.php")
	result := testutil.ScanContent(t, "/app/include.php", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-002")
}

// --- GTSS-TRV-003: Archive Extraction ---

func TestTRV003_ArchiveExtraction_Python(t *testing.T) {
	content := `import zipfile
zf = zipfile.ZipFile('archive.zip')
zf.extractall('/tmp/output')`
	result := testutil.ScanContent(t, "/app/extract.py", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-003")
}

func TestTRV003_ArchiveExtraction_Safe_Python(t *testing.T) {
	content := `import zipfile
zf = zipfile.ZipFile('archive.zip')
zf.extractall('/tmp/output', members=safe_members)`
	result := testutil.ScanContent(t, "/app/extract.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-003")
}

// --- GTSS-TRV-004: Symlink Following ---

func TestTRV004_SymlinkFollowing_Go(t *testing.T) {
	content := `package handler
import "os"
func readLink(path string) {
	target, _ := os.Readlink(path)
	data, _ := os.ReadFile(target)
	_ = data
}`
	result := testutil.ScanContent(t, "/app/symlink.go", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-004")
}

func TestTRV004_Safe_WithValidation(t *testing.T) {
	content := `package handler
import (
	"os"
	"path/filepath"
	"strings"
)
func readLink(path string) {
	target, _ := os.Readlink(path)
	clean := filepath.Clean(target)
	if !strings.HasPrefix(clean, "/safe/") {
		return
	}
}`
	result := testutil.ScanContent(t, "/app/symlink.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-004")
}

// --- GTSS-TRV-005: Template Path Injection ---

func TestTRV005_TemplatePathInjection_JS(t *testing.T) {
	content := `app.get('/view', (req, res) => {
	const template = req.query.page;
	res.render(template);
});`
	result := testutil.ScanContent(t, "/app/routes/view.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-005")
}

func TestTRV005_Safe_StringLiteral(t *testing.T) {
	content := `app.get('/view', (req, res) => {
	res.render('home', { user: req.user });
});`
	result := testutil.ScanContent(t, "/app/routes/view.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-005")
}

// --- GTSS-TRV-006: Prototype Pollution ---

func TestTRV006_PrototypePollution_Spread(t *testing.T) {
	content := `app.post('/profile', (req, res) => {
	const profile = { ...req.body };
	db.save(profile);
});`
	result := testutil.ScanContent(t, "/app/routes/profile.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-006")
}

func TestTRV006_PrototypePollution_ObjectAssign(t *testing.T) {
	content := `const data = Object.assign({}, req.body);`
	result := testutil.ScanContent(t, "/app/routes/profile.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-006")
}

func TestTRV006_PrototypePollution_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/prototype_pollution.ts")
	result := testutil.ScanContent(t, "/app/routes/profile.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-006")
}

// --- GTSS-TRV-007: Express sendFile Path ---

func TestTRV007_ExpressSendFile(t *testing.T) {
	content := `app.get('/download', (req, res) => {
	const filePath = req.query.file;
	res.sendFile(filePath);
});`
	result := testutil.ScanContent(t, "/app/routes/download.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-007")
}

func TestTRV007_ExpressDownload(t *testing.T) {
	content := `const file = req.params.name;
res.download(file);`
	result := testutil.ScanContent(t, "/app/routes/download.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-007")
}

// --- GTSS-TRV-008: Null Byte File Path ---

func TestTRV008_NullByteFilePath_Fixture(t *testing.T) {
	if !testutil.FixtureExists("javascript/vulnerable/path_traversal_nullbyte.ts") {
		t.Skip("null byte fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/vulnerable/path_traversal_nullbyte.ts")
	result := testutil.ScanContent(t, "/app/routes/file.ts", content)
	hasFinding := testutil.HasFinding(result, "GTSS-TRV-008") || testutil.HasFinding(result, "GTSS-TRV-001")
	if !hasFinding {
		t.Errorf("expected traversal finding in path_traversal_nullbyte.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-TRV-009: Render Options Injection ---

func TestTRV009_RenderOptionsInjection_Spread(t *testing.T) {
	content := `app.post('/submit', (req, res) => {
	res.render('form', { ...req.body });
});`
	result := testutil.ScanContent(t, "/app/routes/submit.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-009")
}

func TestTRV009_RenderOptionsInjection_ObjectAssign(t *testing.T) {
	content := `res.render('template', Object.assign({}, req.body));`
	result := testutil.ScanContent(t, "/app/routes/submit.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-009")
}

func TestTRV009_RenderOptionsInjection_QueryParams(t *testing.T) {
	content := `res.render('page', { ...req.query });`
	result := testutil.ScanContent(t, "/app/routes/page.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-009")
}

// --- GTSS-TRV-010: Zip Slip Path Traversal ---

func TestTRV010_ZipSlip_Go_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/zip_slip.go")
	result := testutil.ScanContent(t, "/app/extract.go", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_ZipSlip_Java_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/ZipSlip.java")
	result := testutil.ScanContent(t, "/app/ZipExtractor.java", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_ZipSlip_JS_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/zip_slip.ts")
	result := testutil.ScanContent(t, "/app/extract.ts", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_ZipSlip_Python_Fixture(t *testing.T) {
	content := testutil.LoadFixture(t, "python/vulnerable/zip_slip.py")
	result := testutil.ScanContent(t, "/app/extract.py", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_ZipSlip_Go_Inline(t *testing.T) {
	content := `package handler
import (
	"archive/zip"
	"os"
	"path/filepath"
)
func extract(r *zip.ReadCloser, dest string) {
	for _, f := range r.File {
		outPath := filepath.Join(dest, f.Name)
		os.Create(outPath)
	}
}`
	result := testutil.ScanContent(t, "/app/extract.go", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_ZipSlip_Java_Inline(t *testing.T) {
	content := `import java.util.zip.*;
import java.io.*;
public class Extractor {
    void extract(ZipInputStream zis, String dest) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File destFile = new File(dest, entry.getName());
            new FileOutputStream(destFile);
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Extractor.java", content)
	testutil.MustFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_Safe_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/safe/zip_slip_safe.go")
	result := testutil.ScanContent(t, "/app/extract.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_Safe_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/safe/ZipSlipSafe.java")
	result := testutil.ScanContent(t, "/app/ZipExtractor.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_Safe_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/zip_slip_safe.ts")
	result := testutil.ScanContent(t, "/app/extract.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-010")
}

func TestTRV010_Safe_Python(t *testing.T) {
	content := testutil.LoadFixture(t, "python/safe/zip_slip_safe.py")
	result := testutil.ScanContent(t, "/app/extract.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-TRV-010")
}
