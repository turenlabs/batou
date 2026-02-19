package oauth

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-OAUTH-010: OAuth token in query string
// ---------------------------------------------------------------------------

func TestOAuth010_TokenInQueryString_URLBuild(t *testing.T) {
	content := `const url = "https://api.example.com/resource?access_token=" + token;
fetch(url);`
	result := testutil.ScanContent(t, "/app/api.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth010_TokenInQueryString_FetchURL(t *testing.T) {
	content := `fetch("https://api.example.com/data?access_token=" + accessToken)
  .then(res => res.json());`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth010_TokenInQueryString_TemplateString(t *testing.T) {
	content := "url = f\"https://api.example.com/data?access_token={token}\"\nrequests.get(url)"
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth010_TokenInQueryString_Redirect(t *testing.T) {
	content := `redirect_url = request.GET.get('redirect') + "?access_token=" + token
return HttpResponseRedirect(redirect_url)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth010_TokenInHeader_Safe(t *testing.T) {
	content := `const headers = { Authorization: "Bearer " + accessToken };
fetch("https://api.example.com/data", { headers });`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-010")
}

func TestOAuth010_TokenInAuthHeader_Safe(t *testing.T) {
	content := `headers = {"Authorization": f"Bearer {token}"}
response = requests.get("https://api.example.com/data", headers=headers)`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-010")
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-011: OAuth refresh token exposed client-side or logged
// ---------------------------------------------------------------------------

func TestOAuth011_RefreshTokenLocalStorage(t *testing.T) {
	content := `function handleTokenResponse(data) {
  localStorage.setItem('refresh_token', data.refresh_token);
  localStorage.setItem('access_token', data.access_token);
}`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-011")
}

func TestOAuth011_RefreshTokenSessionStorage(t *testing.T) {
	content := `sessionStorage.setItem('oauth_refresh_token', tokens.refresh);`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-011")
}

func TestOAuth011_RefreshTokenBracketAssign(t *testing.T) {
	content := `localStorage['refresh_token'] = response.refresh_token;`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-011")
}

func TestOAuth011_RefreshTokenConsoleLog(t *testing.T) {
	content := `console.log("Got refresh_token:", data.refresh_token);`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-011")
}

func TestOAuth011_RefreshTokenCookie(t *testing.T) {
	content := `document.cookie = "refresh_token=" + tokens.refresh + "; path=/";`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-OAUTH-011")
}

func TestOAuth011_ServerSideStorage_Safe(t *testing.T) {
	content := `async function handleCallback(code) {
  const tokens = await exchangeCode(code);
  await db.users.update({
    where: { id: userId },
    data: { refreshToken: tokens.refresh_token }
  });
  res.cookie('session', sessionId, { httpOnly: true, secure: true });
}`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-011")
}

func TestOAuth011_HttpOnlyCookie_Safe(t *testing.T) {
	content := `res.cookie('refresh_token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-OAUTH-011")
}
