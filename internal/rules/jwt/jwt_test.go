package jwt

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-JWT-001: JWT none algorithm accepted ---

func TestJWT001_NoneAlg_JS(t *testing.T) {
	content := `const options = { "algorithm": "none" };`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-001")
}

func TestJWT001_VerifyFalse_Python(t *testing.T) {
	content := `payload = jwt.decode(token, verify=False)`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-001")
}

func TestJWT001_AlgorithmsNone_Python(t *testing.T) {
	content := `payload = jwt.decode(token, algorithms=["none"])`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-001")
}

func TestJWT001_AlgNone_Inline(t *testing.T) {
	content := `algorithms = ["none"]`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-001")
}

func TestJWT001_Safe_RS256(t *testing.T) {
	content := `const options = { "algorithm": "RS256" };`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-001")
}

// --- BATOU-JWT-002: JWT hardcoded secret key ---

func TestJWT002_HardcodedSecret_JS(t *testing.T) {
	content := `const token = jwt.sign(payload, "my-super-secret-key-12345678");`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-002")
}

func TestJWT002_SecretAssign_Env(t *testing.T) {
	content := `JWT_SECRET = "hardcoded-secret-value-here"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-002")
}

func TestJWT002_SecretAssign_JS(t *testing.T) {
	content := `const jwt_secret = "this-is-my-secret";`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-002")
}

func TestJWT002_Safe_EnvVar(t *testing.T) {
	content := `const secret = process.env.JWT_SECRET;
const token = jwt.sign(payload, secret);`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-002")
}

// --- BATOU-JWT-003: JWT algorithm confusion RS/HS ---

func TestJWT003_AlgConfusion_HSRS(t *testing.T) {
	content := `algorithms = ["HS256", "RS256"]`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-003")
}

func TestJWT003_AlgConfusion_RSHS(t *testing.T) {
	content := `algorithms = ["RS256", "HS256"]`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-003")
}

func TestJWT003_Safe_SingleAlg(t *testing.T) {
	content := `algorithms = ["RS256"]`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-003")
}

// --- BATOU-JWT-004: JWT not verifying expiration ---

func TestJWT004_IgnoreExpiration_JS(t *testing.T) {
	content := `const options = { ignoreExpiration: true };`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-004")
}

func TestJWT004_VerifyExpFalse_Python(t *testing.T) {
	content := `verify_exp = False`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-004")
}

func TestJWT004_ClockSkewMax_CSharp(t *testing.T) {
	content := `ClockSkew = TimeSpan.MaxValue`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-004")
}

func TestJWT004_Safe_DefaultExpCheck(t *testing.T) {
	content := `const decoded = jwt.verify(token, secret);`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-004")
}

// --- BATOU-JWT-005: JWT not verifying issuer/audience ---

func TestJWT005_VerifyIssFalse_Python(t *testing.T) {
	content := `verify_iss = False`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-005")
}

func TestJWT005_ValidateIssuerFalse_CSharp(t *testing.T) {
	content := `ValidateIssuer = false`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-005")
}

func TestJWT005_ValidateAudienceFalse(t *testing.T) {
	content := `ValidateAudience = false`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-005")
}

func TestJWT005_Safe_ValidateIssuerTrue(t *testing.T) {
	content := `ValidateIssuer = true`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-005")
}

// --- BATOU-JWT-006: JWT weak HMAC secret ---

func TestJWT006_WeakSecret_Short(t *testing.T) {
	content := `const token = jwt.sign(payload, "short");`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-006")
}

func TestJWT006_WeakSecret_Python(t *testing.T) {
	content := `token = jwt.encode(payload, "weak")`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-006")
}

func TestJWT006_Safe_LongSecret(t *testing.T) {
	// 32+ chars should not match the weak secret regex (max 15 chars)
	content := `const token = jwt.sign(payload, "this-is-a-very-long-strong-secret-key-that-is-secure");`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-006")
}

// --- BATOU-JWT-007: JWT token in URL parameter ---

func TestJWT007_TokenInURL_QueryString(t *testing.T) {
	content := `const url = "/api/data?token=eyJhbGciOiJIUz";`
	result := testutil.ScanContent(t, "/app/client.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-007")
}

func TestJWT007_TokenInURL_ReqQuery(t *testing.T) {
	content := `const jwt = req.query["access_token"];`
	result := testutil.ScanContent(t, "/app/routes/auth.ts", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-007")
}

func TestJWT007_Safe_AuthHeader(t *testing.T) {
	content := `const token = req.headers["authorization"];`
	result := testutil.ScanContent(t, "/app/routes/auth.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-007")
}

// --- BATOU-JWT-008: JWT decode without verify ---

func TestJWT008_DecodeNoVerify_Python(t *testing.T) {
	content := `payload = jwt.decode(token, verify=False)`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-008")
}

func TestJWT008_UnverifiedHeader_Python(t *testing.T) {
	content := `header = jwt.get_unverified_header(token)`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-008")
}

func TestJWT008_Base64Decode_Token(t *testing.T) {
	content := `decoded = base64.b64decode(token)`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-008")
}

func TestJWT008_Safe_VerifiedDecode(t *testing.T) {
	content := `payload = jwt.decode(token, key, algorithms=["RS256"])`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-008")
}

// --- BATOU-JWT-009: JWT kid header injection ---

func TestJWT009_KidSQL(t *testing.T) {
	content := `header = {"kid": "' UNION SELECT 'key' --"}`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-009")
}

func TestJWT009_KidPathTraversal(t *testing.T) {
	content := `header = {"kid": "../../../dev/null"}`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-009")
}

func TestJWT009_Safe_StaticKid(t *testing.T) {
	content := `header = {"kid": "my-key-id-001"}`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-009")
}

// --- BATOU-JWT-010: JWT stored in localStorage ---

func TestJWT010_LocalStorageSet(t *testing.T) {
	content := `localStorage.setItem("token", jwtToken);`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-010")
}

func TestJWT010_LocalStorageDirect(t *testing.T) {
	content := `localStorage["access_token"] = response.token;`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustFindRule(t, result, "BATOU-JWT-010")
}

func TestJWT010_Safe_HttpOnlyCookie(t *testing.T) {
	content := `document.cookie = "token=abc; HttpOnly; Secure";`
	result := testutil.ScanContent(t, "/app/login.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JWT-010")
}
