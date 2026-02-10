package crypto

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// --- GTSS-CRY-001: Weak Hashing ---

func TestCRY001_GoMD5(t *testing.T) {
	content := `hash := md5.Sum(password)`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-001")
}

func TestCRY001_GoSHA1(t *testing.T) {
	content := `h := sha1.New()`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-001")
}

func TestCRY001_PythonMD5(t *testing.T) {
	content := `digest = hashlib.md5(password.encode()).hexdigest()`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-001")
}

func TestCRY001_JSMD5(t *testing.T) {
	content := `const hash = crypto.createHash('md5').update(password).digest('hex');`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-001")
}

func TestCRY001_JavaMD5(t *testing.T) {
	content := `MessageDigest md = MessageDigest.getInstance("MD5");`
	result := testutil.ScanContent(t, "/app/Auth.java", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-001")
}

func TestCRY001_Fixture_WeakCrypto_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/weak_crypto.go")
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	hasCrypto := testutil.HasFinding(result, "GTSS-CRY-001") ||
		testutil.HasFinding(result, "GTSS-CRY-003") ||
		testutil.HasFinding(result, "GTSS-CRY-004")
	if !hasCrypto {
		t.Errorf("expected crypto finding in weak_crypto.go, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-CRY-002: Insecure Random ---

func TestCRY002_GoMathRand_SecurityCtx(t *testing.T) {
	content := `package auth
import "math/rand"
func generateToken() string {
	token := rand.Intn(999999)
	return fmt.Sprintf("%06d", token)
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-002")
}

func TestCRY002_PythonRandom_SecurityCtx(t *testing.T) {
	content := `import random
def generate_token():
    token = random.randint(100000, 999999)
    return str(token)`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	hasFinding := testutil.HasFinding(result, "GTSS-CRY-002") || testutil.HasFinding(result, "GTSS-CRY-009")
	if !hasFinding {
		t.Errorf("expected insecure random finding, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestCRY002_JSMathRandom_SecurityCtx(t *testing.T) {
	content := `function generateSessionToken() {
	return Math.random().toString(36).substring(2);
}`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	hasFinding := testutil.HasFinding(result, "GTSS-CRY-002") || testutil.HasFinding(result, "GTSS-CRY-008")
	if !hasFinding {
		t.Errorf("expected insecure random finding, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-CRY-003: Weak Cipher ---

func TestCRY003_GoDES(t *testing.T) {
	content := `cipher, _ := des.NewCipher(key)`
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-003")
}

func TestCRY003_ECBMode(t *testing.T) {
	content := `cipher = AES.new(key, AES.MODE_ECB)`
	result := testutil.ScanContent(t, "/app/crypto.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-003")
}

func TestCRY003_JavaDES(t *testing.T) {
	content := `Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");`
	result := testutil.ScanContent(t, "/app/Crypto.java", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-003")
}

func TestCRY003_Fixture_WeakCrypto_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/weak_crypto.ts")
	result := testutil.ScanContent(t, "/app/crypto.ts", content)
	hasCrypto := testutil.HasFinding(result, "GTSS-CRY-003") ||
		testutil.HasFinding(result, "GTSS-CRY-001") ||
		testutil.HasFinding(result, "GTSS-CRY-004")
	if !hasCrypto {
		t.Errorf("expected crypto finding in weak_crypto.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-CRY-004: Hardcoded IV ---

func TestCRY004_GoByteIV(t *testing.T) {
	content := `iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}`
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-004")
}

func TestCRY004_StringIV(t *testing.T) {
	content := `nonce = "1234567890abcdef"`
	result := testutil.ScanContent(t, "/app/crypto.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-004")
}

// --- GTSS-CRY-005: Insecure TLS ---

func TestCRY005_GoInsecureSkipVerify(t *testing.T) {
	content := `client := &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}`
	result := testutil.ScanContent(t, "/app/client.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-005")
}

func TestCRY005_PythonVerifyFalse(t *testing.T) {
	content := `resp = requests.get(url, verify=False)`
	result := testutil.ScanContent(t, "/app/client.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-005")
}

func TestCRY005_NodeRejectUnauthorized(t *testing.T) {
	content := `const agent = new https.Agent({ rejectUnauthorized: false });`
	result := testutil.ScanContent(t, "/app/client.ts", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-005")
}

func TestCRY005_NodeTLSEnv(t *testing.T) {
	content := `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`
	result := testutil.ScanContent(t, "/app/app.ts", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-005")
}

// --- GTSS-CRY-006: Weak Key Size ---

func TestCRY006_GoRSA1024(t *testing.T) {
	content := `key, _ := rsa.GenerateKey(rand.Reader, 1024)`
	result := testutil.ScanContent(t, "/app/keygen.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-006")
}

func TestCRY006_WeakCurve(t *testing.T) {
	content := `curve := elliptic.P192()`
	result := testutil.ScanContent(t, "/app/keygen.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-006")
}

func TestCRY006_JavaRSA1024(t *testing.T) {
	content := `keyGen.initialize(1024);`
	result := testutil.ScanContent(t, "/app/KeyGen.java", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-006")
}

// --- GTSS-CRY-007: Plaintext Protocol ---

func TestCRY007_HTTP_API(t *testing.T) {
	content := `apiURL := "http://api.production.com/v1/data"`
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-007")
}

func TestCRY007_Safe_Localhost(t *testing.T) {
	content := `url := "http://localhost:8080/health"`
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-CRY-007")
}

func TestCRY007_Safe_Example(t *testing.T) {
	content := `url := "http://example.com/test"`
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-CRY-007")
}

// --- GTSS-CRY-008: JS Math.random() Security ---

func TestCRY008_JSMathRandom_TokenGen(t *testing.T) {
	content := `function generateApiKey() {
	return 'key_' + Math.random().toString(36);
}`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-008")
}

// --- GTSS-CRY-009: Python random Security ---

func TestCRY009_PythonRandom_TokenGen(t *testing.T) {
	content := `import random
def make_api_key():
    return ''.join(random.choice('abcdefghijklmnop') for _ in range(32))`
	result := testutil.ScanContent(t, "/app/auth.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-009")
}

// --- GTSS-CRY-010: Weak PRNG ---

func TestCRY010_JavaUtilRandom(t *testing.T) {
	content := `import java.util.Random;
public class TokenGen {
    public String generateToken() {
        Random rng = new Random();
        return String.valueOf(rng.nextInt());
    }
}`
	result := testutil.ScanContent(t, "/app/TokenGen.java", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-010")
}

func TestCRY010_PHPRand_SecurityCtx(t *testing.T) {
	content := `<?php
$token = rand(100000, 999999);`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-010")
}

// --- GTSS-CRY-011: Predictable Seed ---

func TestCRY011_PythonSeedTime(t *testing.T) {
	content := `import random, time
random.seed(time.time())`
	result := testutil.ScanContent(t, "/app/rng.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

func TestCRY011_PythonSeedFixed(t *testing.T) {
	content := `random.seed(42)`
	result := testutil.ScanContent(t, "/app/rng.py", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

func TestCRY011_GoSeedTime(t *testing.T) {
	content := `rand.Seed(time.Now().UnixNano())`
	result := testutil.ScanContent(t, "/app/rng.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

func TestCRY011_GoSeedFixed(t *testing.T) {
	content := `rand.Seed(12345)`
	result := testutil.ScanContent(t, "/app/rng.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

func TestCRY011_GoNewSourceFixed(t *testing.T) {
	content := `src := rand.NewSource(42)`
	result := testutil.ScanContent(t, "/app/rng.go", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

func TestCRY011_JavaFixedSeed(t *testing.T) {
	content := `Random rng = new Random(12345L);`
	result := testutil.ScanContent(t, "/app/Rng.java", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

func TestCRY011_CSeedTime(t *testing.T) {
	content := `srand(time(NULL));`
	result := testutil.ScanContent(t, "/app/rng.c", content)
	testutil.MustFindRule(t, result, "GTSS-CRY-011")
}

// --- Safe fixture tests ---

func TestCRY_Safe_Go(t *testing.T) {
	if !testutil.FixtureExists("go/safe/crypto_safe.go") {
		t.Skip("safe crypto fixture not available")
	}
	content := testutil.LoadFixture(t, "go/safe/crypto_safe.go")
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-CRY-001")
	testutil.MustNotFindRule(t, result, "GTSS-CRY-003")
}

func TestCRY_Safe_JS(t *testing.T) {
	if !testutil.FixtureExists("javascript/safe/crypto_safe.ts") {
		t.Skip("safe crypto fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/safe/crypto_safe.ts")
	result := testutil.ScanContent(t, "/app/crypto.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-CRY-001")
	testutil.MustNotFindRule(t, result, "GTSS-CRY-003")
}
