package redirect

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-REDIR-001: Server Redirect With User Input ---

func TestREDIR001_Go_HTTPRedirect(t *testing.T) {
	content := `func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusFound)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_Go_FormValueRedirect(t *testing.T) {
	content := `func login(w http.ResponseWriter, r *http.Request) {
	returnTo := r.FormValue("return_to")
	// authenticate...
	http.Redirect(w, r, returnTo, 302)
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_Python_DjangoRedirect(t *testing.T) {
	content := `def login_redirect(request):
    url = request.GET['next']
    return HttpResponseRedirect(request.GET['url'])
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_Python_FlaskRedirect(t *testing.T) {
	content := `@app.route('/redirect')
def handle_redirect():
    url = request.args.get('url')
    return redirect(url)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_JS_ResRedirect(t *testing.T) {
	content := `app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_JS_DirectReqQuery(t *testing.T) {
	content := `app.get('/go', (req, res) => {
  res.redirect(req.query.to);
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_PHP_HeaderLocation(t *testing.T) {
	content := `<?php
$url = $_GET['url'];
header("Location: " . $_GET['url']);
?>`
	result := testutil.ScanContent(t, "/app/redirect.php", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_Ruby_RedirectTo(t *testing.T) {
	content := `def redirect
  redirect_to params[:url]
end`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_Java_SendRedirect(t *testing.T) {
	content := `String url = request.getParameter("url");
response.sendRedirect(url);`
	result := testutil.ScanContent(t, "/app/Servlet.java", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-001")
}

// --- GTSS-REDIR-001: Safe patterns (should NOT trigger) ---

func TestREDIR001_Safe_GoStaticRedirect(t *testing.T) {
	content := `func handler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-REDIR-001")
}

func TestREDIR001_Safe_JSStaticRedirect(t *testing.T) {
	content := `app.get('/home', (req, res) => {
  res.redirect('/dashboard');
});`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-REDIR-001")
}

// --- GTSS-REDIR-002: Bypassable URL Allowlist ---

func TestREDIR002_JS_URLIncludes(t *testing.T) {
	content := `app.get('/redirect', (req, res) => {
  const url = req.query.to;
  if (url.includes("allowed.com")) {
    res.redirect(url);
  }
});`
	result := testutil.ScanContent(t, "/app/redirect.ts", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-002")
}

func TestREDIR002_JS_URLIndexOf(t *testing.T) {
	content := `function doRedirect(req, res) {
  const redirectUrl = req.query.url;
  if (redirectUrl.indexOf("trusted.com") !== -1) {
    res.redirect(redirectUrl);
  }
}`
	result := testutil.ScanContent(t, "/app/redirect.ts", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-002")
}

func TestREDIR002_JS_StartsWithHTTP(t *testing.T) {
	content := `function handleRedirect(req, res) {
  const url = req.query.url;
  if (url.startsWith("http")) {
    res.redirect(url);
  }
}`
	result := testutil.ScanContent(t, "/app/redirect.ts", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-002")
}

func TestREDIR002_Python_InOperator(t *testing.T) {
	content := `def redirect_view(request):
    url = request.GET.get('url')
    if "allowed.com" in url:
        return redirect(url)
`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-REDIR-002")
}

func TestREDIR002_Safe_NoRedirectContext(t *testing.T) {
	// url.includes in code that has nothing to do with redirects
	content := `function processData(items) {
  const url = getApiUrl();
  if (url.includes("staging")) {
    console.log("Using staging API");
  }
}`
	result := testutil.ScanContent(t, "/app/api.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-REDIR-002")
}

// --- Fixture tests ---

func TestREDIR001_Fixture_Go_OpenRedirect(t *testing.T) {
	if !testutil.FixtureExists("go/vulnerable/open_redirect.go") {
		t.Skip("fixture not available")
	}
	content := testutil.LoadFixture(t, "go/vulnerable/open_redirect.go")
	result := testutil.ScanContent(t, "/app/handler.go", content)
	hasRedirect := testutil.HasFinding(result, "GTSS-REDIR-001") || testutil.HasFinding(result, "GTSS-GEN-004")
	if !hasRedirect {
		t.Errorf("expected redirect finding in open_redirect.go, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestREDIR001_Fixture_JS_OpenRedirect(t *testing.T) {
	if !testutil.FixtureExists("javascript/vulnerable/open_redirect.ts") {
		t.Skip("fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/vulnerable/open_redirect.ts")
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	hasRedirect := testutil.HasFinding(result, "GTSS-REDIR-001") || testutil.HasFinding(result, "GTSS-GEN-004")
	if !hasRedirect {
		t.Errorf("expected redirect finding in open_redirect.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}
