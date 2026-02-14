package secrets

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-SEC-001: Hardcoded Password ---
// NOTE: SEC-001 excludes test files (paths matching fixtures?/), so we use
// non-test-looking file paths for vulnerable tests.

func TestSEC001_HardcodedPassword_Go(t *testing.T) {
	content := `package config
var password = "SuperSecretP@ss123"`
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-001")
}

func TestSEC001_HardcodedPassword_Python(t *testing.T) {
	content := `password = "hunter2secret"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-001")
}

func TestSEC001_HardcodedPassword_JS(t *testing.T) {
	content := `const apikey = "sk_live_abc123def456ghi";`
	result := testutil.ScanContent(t, "/app/config.ts", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-001")
}

func TestSEC001_HardcodedPassword_PHP(t *testing.T) {
	content := `<?php $password = "dbpass1234"; ?>`
	result := testutil.ScanContent(t, "/app/config.php", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-001")
}

func TestSEC001_Safe_Placeholder(t *testing.T) {
	content := `password = "changeme"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-SEC-001")
}

func TestSEC001_Safe_EnvVar(t *testing.T) {
	content := `password = "${DB_PASSWORD}"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-SEC-001")
}

func TestSEC001_Fixture_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/hardcoded_secret.go")
	result := testutil.ScanContent(t, "/app/config.go", content)
	hasSEC := testutil.HasFinding(result, "GTSS-SEC-001") || testutil.HasFinding(result, "GTSS-SEC-005")
	if !hasSEC {
		t.Errorf("expected secret finding in hardcoded_secret.go, got: %v", testutil.FindingRuleIDs(result))
	}
}

func TestSEC001_Fixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/hardcoded_secret.ts")
	result := testutil.ScanContent(t, "/app/config.ts", content)
	hasSEC := testutil.HasFinding(result, "GTSS-SEC-001") ||
		testutil.HasFinding(result, "GTSS-SEC-002") ||
		testutil.HasFinding(result, "GTSS-SEC-005")
	if !hasSEC {
		t.Errorf("expected secret finding in hardcoded_secret.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-SEC-002: API Key Exposure ---

func TestSEC002_AWSAccessKey(t *testing.T) {
	content := `aws_key = "AKIAIOSFODNN7EXAMPLE"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-002")
}

func TestSEC002_GitHubToken(t *testing.T) {
	content := `token := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"`
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-002")
}

func TestSEC002_StripeKey(t *testing.T) {
	content := `const key = "sk_live_51H8OeJKL8vYa3mNoPq1R2sT3u";`
	result := testutil.ScanContent(t, "/app/payment.ts", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-002")
}

func TestSEC002_SlackToken(t *testing.T) {
	content := `SLACK_TOKEN = "xoxb-1234567890-abcdefghij"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-002")
}

// --- GTSS-SEC-003: Private Key in Code ---

func TestSEC003_RSAPrivateKey(t *testing.T) {
	content := `key = """-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJ+...
-----END RSA PRIVATE KEY-----"""`
	result := testutil.ScanContent(t, "/app/keys.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-003")
}

func TestSEC003_ECPrivateKey(t *testing.T) {
	content := `const pk = "-----BEGIN EC PRIVATE KEY-----";`
	result := testutil.ScanContent(t, "/app/keys.ts", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-003")
}

func TestSEC003_GenericPrivateKey(t *testing.T) {
	content := `-----BEGIN PRIVATE KEY-----`
	result := testutil.ScanContent(t, "/app/cert.go", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-003")
}

// --- GTSS-SEC-004: Connection String ---

func TestSEC004_PostgresURI(t *testing.T) {
	content := `dsn := "postgres://admin:s3cretP4ss@db.prod.internal:5432/mydb"`
	result := testutil.ScanContent(t, "/app/db.go", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-004")
}

func TestSEC004_MongoDBURI(t *testing.T) {
	content := `MONGO_URI = "mongodb://root:password123@mongo.prod:27017/app"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-004")
}

func TestSEC004_Safe_Placeholder(t *testing.T) {
	content := `dsn := "postgres://user:password@localhost:5432/db"`
	result := testutil.ScanContent(t, "/app/db.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-SEC-004")
}

func TestSEC004_Safe_EnvVar(t *testing.T) {
	content := `dsn := "postgres://${DB_USER}:${DB_PASS}@localhost:5432/db"`
	result := testutil.ScanContent(t, "/app/db.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-SEC-004")
}

// --- GTSS-SEC-005: JWT Secret ---

func TestSEC005_JWTSign(t *testing.T) {
	content := `const token = jwt.sign(payload, "my-jwt-secret-key-123");`
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-005")
}

func TestSEC005_JWTSecretAssignment(t *testing.T) {
	content := `jwt_secret = "supersecretjwtkey2024"`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-005")
}

func TestSEC005_Fixture_JWT(t *testing.T) {
	if !testutil.FixtureExists("javascript/vulnerable/jwt_none_algo.ts") {
		t.Skip("JWT fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/vulnerable/jwt_none_algo.ts")
	result := testutil.ScanContent(t, "/app/auth.ts", content)
	hasSEC := testutil.HasFinding(result, "GTSS-SEC-005") || testutil.HasFinding(result, "GTSS-SEC-001")
	if !hasSEC {
		t.Errorf("expected secret/JWT finding in jwt_none_algo.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- GTSS-SEC-006: Environment Leak ---

func TestSEC006_EnvFile(t *testing.T) {
	content := `DATABASE_PASSWORD=supersecret123
API_SECRET_KEY=abc123def456`
	result := testutil.ScanContent(t, "/app/.env", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-006")
}

func TestSEC006_LoggingEnvVar_JS(t *testing.T) {
	content := `console.log("API Key: " + process.env.API_SECRET_KEY);`
	result := testutil.ScanContent(t, "/app/debug.ts", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-006")
}

func TestSEC006_LoggingEnvVar_Python(t *testing.T) {
	content := `print(os.environ.get('SECRET_KEY'))`
	result := testutil.ScanContent(t, "/app/debug.py", content)
	testutil.MustFindRule(t, result, "GTSS-SEC-006")
}

// --- Safe fixture tests ---

func TestSEC_Safe_Secrets_Go(t *testing.T) {
	if !testutil.FixtureExists("go/safe/secrets_safe.go") {
		t.Skip("safe secrets fixture not available")
	}
	content := testutil.LoadFixture(t, "go/safe/secrets_safe.go")
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-SEC-001")
	testutil.MustNotFindRule(t, result, "GTSS-SEC-004")
}
