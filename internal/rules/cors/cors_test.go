package cors

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-CORS-001: Wildcard Origin with Credentials ---

func TestCORS001_Express_WildcardWithCreds(t *testing.T) {
	content := `const cors = require('cors');
app.use(cors({
  origin: '*',
  credentials: true
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-001")
}

func TestCORS001_Go_WildcardWithCreds(t *testing.T) {
	content := `func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}`
	result := testutil.ScanContent(t, "/app/middleware.go", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-001")
}

func TestCORS001_Django_AllowAllWithCreds(t *testing.T) {
	content := `CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-001")
}

func TestCORS001_Spring_CrossOriginStar(t *testing.T) {
	content := `@CrossOrigin(origins = "*")
@RestController
public class ApiController {
    // allowCredentials="true" is default in some configs
}`
	// Spring wildcard without credentials is low severity
	result := testutil.ScanContent(t, "/app/ApiController.java", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-001")
}

func TestCORS001_Flask_WildcardWithCreds(t *testing.T) {
	content := `from flask_cors import CORS
CORS(app, origins="*")
app.config['CORS_SUPPORTS_CREDENTIALS'] = True
supports_credentials = True`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-001")
}

func TestCORS001_Safe_SpecificOrigin(t *testing.T) {
	content := `const cors = require('cors');
app.use(cors({
  origin: 'https://myapp.example.com',
  credentials: true
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-CORS-001")
}

func TestCORS001_Safe_WildcardNoCreds(t *testing.T) {
	// Wildcard without credentials is low severity, not medium
	content := `app.use(cors({
  origin: '*'
}));`
	result := testutil.ScanContent(t, "/app/server.js", content)
	// Should find with LOW severity, not medium
	findings := testutil.FindingsByRule(result, "GTSS-CORS-001")
	if len(findings) == 0 {
		t.Error("expected CORS-001 finding for wildcard origin")
		return
	}
	for _, f := range findings {
		if f.Severity > 1 { // > Low
			t.Errorf("expected LOW severity for wildcard without credentials, got %s", f.Severity)
		}
	}
}

// --- GTSS-CORS-002: Reflected Origin ---

func TestCORS002_Express_ReflectedOrigin(t *testing.T) {
	content := `app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});`
	result := testutil.ScanContent(t, "/app/middleware.js", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-002")
}

func TestCORS002_Go_ReflectedOrigin(t *testing.T) {
	content := `func corsHandler(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	w.Header().Set("Access-Control-Allow-Origin", origin)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-002")
}

func TestCORS002_Python_ReflectedOrigin(t *testing.T) {
	content := `origin = request.headers.get('origin')
response["Access-Control-Allow-Origin"] = origin`
	result := testutil.ScanContent(t, "/app/middleware.py", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-002")
}

func TestCORS002_PHP_ReflectedOrigin(t *testing.T) {
	content := `<?php
header("Access-Control-Allow-Origin: " . $_SERVER["HTTP_ORIGIN"]);`
	result := testutil.ScanContent(t, "/app/cors.php", content)
	testutil.MustFindRule(t, result, "GTSS-CORS-002")
}

func TestCORS002_Safe_ValidatedOrigin(t *testing.T) {
	content := `const allowedOrigins = ['https://myapp.com', 'https://admin.myapp.com'];
const origin = req.headers.origin;
if (allowedOrigins.includes(origin)) {
  res.header("Access-Control-Allow-Origin", req.headers.origin);
}`
	result := testutil.ScanContent(t, "/app/middleware.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-CORS-002")
}

func TestCORS002_Safe_Go_ValidatedOrigin(t *testing.T) {
	content := `func corsHandler(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	isAllowedOrigin := allowedOrigins[origin]
	if isAllowedOrigin {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-CORS-002")
}
