package oauth

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-OAUTH-001: OAuth state parameter missing (CSRF)
// ---------------------------------------------------------------------------

func TestOAuth001_NoState_Fires(t *testing.T) {
	content := `function login() {
  const u = "https://idp.example.com/authorize?client_id=abc&response_type=code&redirect_uri=cb";
  window.location = u;
}`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-001")
}

func TestOAuth001_StateOnSameLine_Safe(t *testing.T) {
	// reOAuthStateParam matches on the same authorize line -> suppressed.
	content := `const u = "https://idp.example.com/authorize?client_id=abc&response_type=code&state=" + s;`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-001")
}

func TestOAuth001_StateNearby_Safe(t *testing.T) {
	// state appears within the +/-5 line window via hasNearbyPattern -> suppressed.
	content := `const state = crypto.randomUUID();
session.state = state;
const u = "https://idp.example.com/authorize?client_id=abc&response_type=code&redirect_uri=cb";
window.location = u;`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-001")
}

func TestOAuth001_CommentLine_Safe(t *testing.T) {
	// A comment line that would otherwise match must be skipped by isComment.
	content := `// const u = "https://idp.example.com/authorize?client_id=abc&response_type=code&redirect_uri=cb";`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-001")
}

func TestOAuth001_Metadata(t *testing.T) {
	r := &OAuthNoState{}
	if r.ID() != "BATOU-OAUTH-001" {
		t.Errorf("ID = %q", r.ID())
	}
	if r.Name() != "OAuthNoState" {
		t.Errorf("Name = %q", r.Name())
	}
	if r.DefaultSeverity() != rules.High {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
	if len(r.Languages()) == 0 {
		t.Error("no Languages")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-002: OAuth implicit grant flow (deprecated)
// ---------------------------------------------------------------------------

func TestOAuth002_ResponseTypeToken_Fires(t *testing.T) {
	content := `const params = { response_type: 'token', client_id: cid };`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-002")
}

func TestOAuth002_GrantTypeImplicit_Fires(t *testing.T) {
	// Bare-key form: reOAuthImplicitFlow's grant_type=["']implicit["'] alternation.
	content := `grant_type = "implicit"`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-002")
}

func TestOAuth002_ImplicitFlowProse_Fires(t *testing.T) {
	// reOAuthImplicitFlow's implicit\s*(?:grant|flow) alternation.
	content := `flow = ImplicitGrant(client_id=cid)`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-002")
}

func TestOAuth002_AuthCodeFlow_Safe(t *testing.T) {
	content := `const params = { response_type: 'code', client_id: cid };`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-002")
}

func TestOAuth002_CommentLine_Safe(t *testing.T) {
	content := `# response_type: 'token' is deprecated, do not use`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-002")
}

func TestOAuth002_Metadata(t *testing.T) {
	r := &OAuthImplicitGrant{}
	if r.ID() != "BATOU-OAUTH-002" || r.Name() != "OAuthImplicitGrant" {
		t.Errorf("ID/Name mismatch: %q/%q", r.ID(), r.Name())
	}
	if r.DefaultSeverity() != rules.Medium {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-003: OAuth redirect_uri not validated
// ---------------------------------------------------------------------------

func TestOAuth003_RedirectFromUserInput_Fires(t *testing.T) {
	content := `redirect_uri = request.args.get("redirect")
oauth_redirect(redirect_uri)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-003")
}

func TestOAuth003_RedirectConcat_Fires(t *testing.T) {
	content := `const redirect_uri = "https://app.example.com/cb?next=" + userInput;`
	result := testutil.ScanContent(t, "/app/oauth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-003")
}

func TestOAuth003_ValidatedRedirect_Safe(t *testing.T) {
	// validate_redirect within the +/-10 window suppresses the finding.
	content := `redirect_uri = request.args.get("redirect")
if not validate_redirect(redirect_uri):
    abort(400)
oauth_redirect(redirect_uri)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-003")
}

func TestOAuth003_CommentLine_Safe(t *testing.T) {
	content := `// redirect_uri = request.args.get("redirect")`
	result := testutil.ScanContent(t, "/app/oauth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-003")
}

func TestOAuth003_Metadata(t *testing.T) {
	r := &OAuthOpenRedirect{}
	if r.ID() != "BATOU-OAUTH-003" || r.Name() != "OAuthOpenRedirect" {
		t.Errorf("ID/Name mismatch: %q/%q", r.ID(), r.Name())
	}
	if r.DefaultSeverity() != rules.High {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-004: OAuth token in URL fragment
// ---------------------------------------------------------------------------

func TestOAuth004_TokenFromHash_Fires(t *testing.T) {
	content := `const token = window.location.hash.split("access_token=")[1];`
	result := testutil.ScanContent(t, "/app/callback.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-004")
}

func TestOAuth004_HashRoutingNoCredential_Safe(t *testing.T) {
	// File-level suppression: hash routing present, no credential keywords.
	content := `import { createHashRouter } from 'react-router-dom';
const router = createHashRouter(routes);
function onChange() { window.location.hash = "#/home"; }`
	result := testutil.ScanContent(t, "/app/router.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-004")
}

func TestOAuth004_PerLineRoutingSuppressed_StillFiresElsewhere(t *testing.T) {
	// File has credential keyword (so file-level gate passes), but one line is
	// pure routing (per-line skip) while another extracts the token (fires).
	content := `function route() { window.location.hash = "#/dashboard"; }
const access_token = window.location.hash.match(/access_token=([^&]+)/)[1];`
	result := testutil.ScanContent(t, "/app/oauth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-004")
}

func TestOAuth004_CommentLine_Safe(t *testing.T) {
	// Comment line skipped; credential keyword present so file-level gate passes.
	content := `// access_token extraction example
// const t = window.location.hash;`
	result := testutil.ScanContent(t, "/app/oauth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-004")
}

func TestOAuth004_Metadata(t *testing.T) {
	r := &OAuthTokenFragment{}
	if r.ID() != "BATOU-OAUTH-004" || r.Name() != "OAuthTokenFragment" {
		t.Errorf("ID/Name mismatch: %q/%q", r.ID(), r.Name())
	}
	if r.DefaultSeverity() != rules.Medium {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-005: PKCE not used (additional safe branches)
// ---------------------------------------------------------------------------

func TestOAuth005_PKCEHintConfig_Safe(t *testing.T) {
	// reOAuthPKCEHint (usePkce / response_mode) suppresses.
	content := `const cfg = {
  response_type: 'code',
  client_id: cid,
  usePkce: true
};`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-005")
}

func TestOAuth005_CommentLine_Safe(t *testing.T) {
	content := `// response_type: 'code' without pkce here`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-005")
}

func TestOAuth005_Metadata(t *testing.T) {
	r := &OAuthNoPKCE{}
	if r.Name() != "OAuthNoPKCE" {
		t.Errorf("Name = %q", r.Name())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
	if len(r.Languages()) == 0 {
		t.Error("no Languages")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-006: OAuth client secret exposed in frontend
// ---------------------------------------------------------------------------

func TestOAuth006_ClientSecretFrontendContext_Fires(t *testing.T) {
	// Frontend context via document. present -> fires.
	content := `document.addEventListener('load', () => {});
const clientSecret = "abcdef123456";`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-006")
}

func TestOAuth006_ClientSecretTsxPath_Fires(t *testing.T) {
	// .tsx suffix triggers the frontend gate even without document/window.
	content := `const config = { client_secret: "supersecretvalue" };`
	result := testutil.ScanContent(t, "/app/Login.tsx", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-006")
}

func TestOAuth006_BackendNoFrontendContext_Safe(t *testing.T) {
	// No frontend context and a backend path (no src/public/static, not jsx/tsx).
	content := `const clientSecret = "abcdef123456";`
	result := testutil.ScanContent(t, "/backend/config.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-006")
}

func TestOAuth006_CommentLine_Safe(t *testing.T) {
	content := `// const clientSecret = "abcdef123456";`
	result := testutil.ScanContent(t, "/src/login.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-006")
}

func TestOAuth006_Metadata(t *testing.T) {
	r := &OAuthClientSecretFE{}
	if r.ID() != "BATOU-OAUTH-006" || r.Name() != "OAuthClientSecretFE" {
		t.Errorf("ID/Name mismatch: %q/%q", r.ID(), r.Name())
	}
	if r.DefaultSeverity() != rules.High {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-007: OAuth scope not validated server-side
// ---------------------------------------------------------------------------

func TestOAuth007_ScopeFromUser_Fires(t *testing.T) {
	content := `scope = request.args.get("scope")
build_auth_url(scope)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-007")
}

func TestOAuth007_ScopeConcat_Fires(t *testing.T) {
	content := `scopes = base_scopes + req.scope`
	result := testutil.ScanContent(t, "/app/oauth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-007")
}

func TestOAuth007_ValidatedScope_Safe(t *testing.T) {
	content := `scope = request.args.get("scope")
if scope not in allowed_scopes:
    abort(403)
build_auth_url(scope)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-007")
}

func TestOAuth007_CommentLine_Safe(t *testing.T) {
	content := `// scope = request.args.get("scope")`
	result := testutil.ScanContent(t, "/app/oauth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-007")
}

func TestOAuth007_Metadata(t *testing.T) {
	r := &OAuthScopeNotValidated{}
	if r.ID() != "BATOU-OAUTH-007" || r.Name() != "OAuthScopeNotValidated" {
		t.Errorf("ID/Name mismatch: %q/%q", r.ID(), r.Name())
	}
	if r.DefaultSeverity() != rules.Medium {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-008: OAuth token stored in localStorage
// ---------------------------------------------------------------------------

func TestOAuth008_LocalStorageSetItem_Fires(t *testing.T) {
	content := `localStorage.setItem("access_token", token);`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-008")
}

func TestOAuth008_LocalStorageBracket_Fires(t *testing.T) {
	content := `localStorage["refresh_token"] = data.refresh;`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-008")
}

func TestOAuth008_NonTokenKey_Safe(t *testing.T) {
	content := `localStorage.setItem("theme", "dark");`
	result := testutil.ScanContent(t, "/app/ui.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-008")
}

func TestOAuth008_CommentLine_Safe(t *testing.T) {
	content := `// localStorage.setItem("access_token", token);`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-008")
}

func TestOAuth008_Metadata(t *testing.T) {
	r := &OAuthTokenLocalStorage{}
	if r.Name() != "OAuthTokenLocalStorage" {
		t.Errorf("Name = %q", r.Name())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-009: OpenID Connect nonce not validated
// ---------------------------------------------------------------------------

func TestOAuth009_NoNonce_Fires(t *testing.T) {
	// OIDC auth request, no nonce anywhere -> "missing nonce" branch.
	content := `const url = "https://idp.example.com/oauth2/authorize?response_type=code";
window.location = url;`
	result := testutil.ScanContent(t, "/app/oidc.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-009")
}

func TestOAuth009_NoncePresentNotVerified_Fires(t *testing.T) {
	// nonce present in file but no verify -> "nonce not verified" branch.
	content := `const params = { scope: "openid profile", nonce: generateNonce() };
const url = "https://idp.example.com/oauth2/authorize";`
	result := testutil.ScanContent(t, "/app/oidc.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-009")
}

func TestOAuth009_NonceVerified_Safe(t *testing.T) {
	// nonce present AND verified -> suppressed.
	content := `const params = { scope: "openid profile", nonce: savedNonce };
const url = "https://idp.example.com/oauth2/authorize";
if (claims["nonce"] !== savedNonce) { throw new Error("nonce mismatch"); }`
	result := testutil.ScanContent(t, "/app/oidc.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-009")
}

func TestOAuth009_NoOidcRequest_Safe(t *testing.T) {
	// Bare keyword mentions no longer trigger (tightened pattern).
	content := `const config = { openId: { issuer: "https://idp" } };
useOpenId(config);`
	result := testutil.ScanContent(t, "/app/oidc.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-009")
}

func TestOAuth009_CommentLine_Safe(t *testing.T) {
	content := `// const url = "https://idp.example.com/oauth2/authorize?response_type=code";`
	result := testutil.ScanContent(t, "/app/oidc.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-009")
}

func TestOAuth009_Metadata(t *testing.T) {
	r := &OIDCNoNonce{}
	if r.ID() != "BATOU-OAUTH-009" || r.Name() != "OIDCNoNonce" {
		t.Errorf("ID/Name mismatch: %q/%q", r.ID(), r.Name())
	}
	if r.DefaultSeverity() != rules.Medium {
		t.Errorf("Severity = %v", r.DefaultSeverity())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-010 / 011: metadata coverage for ext rules
// ---------------------------------------------------------------------------

func TestOAuth010_Metadata(t *testing.T) {
	r := &OAuthTokenQueryString{}
	if r.Name() != "OAuthTokenQueryString" {
		t.Errorf("Name = %q", r.Name())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
	if len(r.Languages()) == 0 {
		t.Error("no Languages")
	}
}

func TestOAuth010_BareQueryStringMediumConf(t *testing.T) {
	// ?access_token= with no url/http/fetch/redirect context -> medium conf branch.
	content := `const q = "?access_token=abc";`
	result := testutil.ScanContent(t, "/app/misc.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
	for _, f := range testutil.FindingsByRule(result, "BATOU-OAUTH-010") {
		if f.Confidence != "medium" {
			t.Errorf("expected medium confidence, got %q", f.Confidence)
		}
	}
}

func TestOAuth010_TokenInURLVar_Fires(t *testing.T) {
	// reOAuthTokenInURL arm: endpoint var assigned a URL with ?access_token=.
	content := `endpoint = base_url + "?access_token=" + token`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth010_QueryStringWithURLContext_HighConf(t *testing.T) {
	// Bare ?access_token= but line contains "http" -> high-confidence arm.
	content := `const s = "http://x?access_token=abc";`
	result := testutil.ScanContent(t, "/app/misc.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
	for _, f := range testutil.FindingsByRule(result, "BATOU-OAUTH-010") {
		if f.Confidence != "high" {
			t.Errorf("expected high confidence, got %q", f.Confidence)
		}
	}
}

func TestOAuth010_CommentLine_Safe(t *testing.T) {
	content := `// const url = "https://api.example.com/r?access_token=" + t;`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth011_Metadata(t *testing.T) {
	r := &OAuthRefreshTokenExposed{}
	if r.Name() != "OAuthRefreshTokenExposed" {
		t.Errorf("Name = %q", r.Name())
	}
	if r.Description() == "" {
		t.Error("empty Description")
	}
}

// ---------------------------------------------------------------------------
// Helper coverage: truncate, hasNearbyPattern
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	// Short string is returned unchanged.
	if got := truncate("short", 120); got != "short" {
		t.Errorf("truncate(short) = %q", got)
	}
	// Long string is truncated with an ellipsis.
	long := strings.Repeat("x", 130)
	got := truncate(long, 120)
	if len(got) != 123 { // 120 + "..."
		t.Errorf("truncate len = %d, want 123", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncate did not append ellipsis: %q", got)
	}
}

func TestHasNearbyPattern(t *testing.T) {
	lines := []string{
		"line0",
		"const state = randomBytes();",
		"line2",
		"line3",
	}
	// Window around idx 2 (+/-5) reaches line 1, which matches the state param.
	if !hasNearbyPattern(lines, 2, 5, 5, reOAuthStateParam) {
		t.Error("expected hasNearbyPattern to find state within window")
	}
	// No match anywhere -> false. Use a window that clamps at both ends.
	plain := []string{"a", "b", "c"}
	if hasNearbyPattern(plain, 1, 5, 5, reOAuthStateParam) {
		t.Error("expected no match in plain lines")
	}
	// Narrow window that excludes the matching line -> false (start clamp + after=0).
	if hasNearbyPattern(lines, 3, 0, 0, reOAuthStateParam) {
		t.Error("expected narrow window at idx 3 to miss the state line")
	}
}

func TestIsComment(t *testing.T) {
	cases := map[string]bool{
		"// x":      true,
		"# x":       true,
		"* x":       true,
		"/* x":      true,
		"<!-- x":    true,
		"code line": false,
		"":          false,
	}
	for in, want := range cases {
		if got := isComment(in); got != want {
			t.Errorf("isComment(%q) = %v, want %v", in, got, want)
		}
	}
}
