package encoding

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-ENC-009: UTF-7 XSS bypass (Content-Type without charset)
// ---------------------------------------------------------------------------

func TestENC009_ContentTypeNoCharset(t *testing.T) {
	content := `app.get('/page', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send('<html>' + userData + '</html>');
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-009")
}

func TestENC009_ContentTypeNoCharset_Python(t *testing.T) {
	content := `def handler(request):
    response = HttpResponse(content)
    response.set('Content-Type', 'text/html')
    response.write(user_data)
    return response`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-009")
}

func TestENC009_ContentTypeWithCharset_Safe(t *testing.T) {
	content := `app.get('/page', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send('<html>' + data + '</html>');
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-009")
}

func TestENC009_ContentTypeCharsetNextLine_Safe(t *testing.T) {
	content := `app.get('/page', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(data);
});`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-009")
}

func TestENC009_NoUserOutput_Safe(t *testing.T) {
	// Just config, no output functions
	content := `const config = {
  contentType: 'text/html'
};`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-009")
}

// ---------------------------------------------------------------------------
// BATOU-ENC-010: URL decode without path normalization
// ---------------------------------------------------------------------------

func TestENC010_DecodeURIWithFileOp(t *testing.T) {
	content := `app.get('/files/:name', (req, res) => {
  const filename = decodeURIComponent(req.params.name);
  const data = fs.readFile('./uploads/' + filename, callback);
  res.send(data);
});`
	result := testutil.ScanContent(t, "/app/files.js", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-010")
}

func TestENC010_UnescapeWithOpen_Python(t *testing.T) {
	content := `import urllib
def download(request):
    filename = urllib.unquote(request.GET.get('file'))
    with open('/uploads/' + filename) as f:
        return f.read()`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-010")
}

func TestENC010_DecodeWithNormalization_Safe(t *testing.T) {
	content := `app.get('/files/:name', (req, res) => {
  const filename = decodeURIComponent(req.params.name);
  const safePath = path.normalize(filename);
  const fullPath = path.resolve('./uploads', safePath);
  fs.readFile(fullPath, callback);
});`
	result := testutil.ScanContent(t, "/app/files.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-010")
}

func TestENC010_DecodeWithClean_Go_Safe(t *testing.T) {
	content := `func handler(w http.ResponseWriter, r *http.Request) {
	name, _ := url.QueryUnescape(r.URL.Query().Get("file"))
	clean := filepath.Clean(name)
	data, _ := os.ReadFile(filepath.Join("uploads", clean))
	w.Write(data)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-010")
}

func TestENC010_DecodeNoFileOps_Safe(t *testing.T) {
	content := `const decoded = decodeURIComponent(searchQuery);
const results = search(decoded);
res.json(results);`
	result := testutil.ScanContent(t, "/app/search.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-010")
}
