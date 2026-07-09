package ruby

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-RB-021: JWT.decode with signature verification disabled
// ==========================================================================

func TestRB021_DecodeFalse_Vulnerable(t *testing.T) {
	content := `payload = JWT.decode(token, nil, false)`
	result := testutil.ScanContent(t, "/app/services/auth.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-021")
}

func TestRB021_VerifyFalse_Vulnerable(t *testing.T) {
	content := `payload = JWT.decode(token, secret, true, { verify: false })`
	result := testutil.ScanContent(t, "/app/services/auth.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-021")
}

func TestRB021_AlgNone_Vulnerable(t *testing.T) {
	content := `payload = JWT.decode(token, nil, true, algorithm: 'none')`
	result := testutil.ScanContent(t, "/app/services/auth.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-021")
}

func TestRB021_VerifiedDecode_Safe(t *testing.T) {
	content := `payload = JWT.decode(token, secret, true, { algorithm: 'HS256' })`
	result := testutil.ScanContent(t, "/app/services/auth.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-021")
}

// ==========================================================================
// BATOU-RB-022: RSA key size < 2048
// ==========================================================================

func TestRB022_WeakKey1024_Vulnerable(t *testing.T) {
	content := `key = OpenSSL::PKey::RSA.new(1024)`
	result := testutil.ScanContent(t, "/app/lib/crypto.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-022")
}

func TestRB022_Generate512_Vulnerable(t *testing.T) {
	content := `key = OpenSSL::PKey::RSA.generate(512)`
	result := testutil.ScanContent(t, "/app/lib/crypto.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-022")
}

func TestRB022_Strong2048_Safe(t *testing.T) {
	content := `key = OpenSSL::PKey::RSA.new(2048)
key4096 = OpenSSL::PKey::RSA.generate(4096)`
	result := testutil.ScanContent(t, "/app/lib/crypto.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-022")
}

// ==========================================================================
// BATOU-RB-023: RSA hardcoded passphrase
// ==========================================================================

func TestRB023_LiteralPassphrase_Vulnerable(t *testing.T) {
	content := `key = OpenSSL::PKey::RSA.new(pem_data, "hunter2pass")`
	result := testutil.ScanContent(t, "/app/lib/crypto.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-023")
}

func TestRB023_EnvPassphrase_Safe(t *testing.T) {
	content := `key = OpenSSL::PKey::RSA.new(pem_data, ENV["RSA_PASSPHRASE"])`
	result := testutil.ScanContent(t, "/app/lib/crypto.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-023")
}

func TestRB023_NoPassphrase_Safe(t *testing.T) {
	content := `key = OpenSSL::PKey::RSA.new(2048)`
	result := testutil.ScanContent(t, "/app/lib/crypto.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-023")
}

// ==========================================================================
// BATOU-RB-024: sslmode disable
// ==========================================================================

func TestRB024_SSLModeDisable_Vulnerable(t *testing.T) {
	content := `conn = PG.connect(host: "db", sslmode: "disable")`
	result := testutil.ScanContent(t, "/app/lib/db.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-024")
}

func TestRB024_SSLModeRequire_Safe(t *testing.T) {
	content := `conn = PG.connect(host: "db", sslmode: "require")`
	result := testutil.ScanContent(t, "/app/lib/db.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-024")
}

// ==========================================================================
// BATOU-RB-025: SHA-224 password hashing
// ==========================================================================

func TestRB025_SHA224Password_Vulnerable(t *testing.T) {
	content := `digest = Digest::SHA224.hexdigest(password)`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-025")
}

func TestRB025_SHA224Checksum_Safe(t *testing.T) {
	content := `file_checksum = Digest::SHA224.hexdigest(file_contents)`
	result := testutil.ScanContent(t, "/app/lib/checksum.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-025")
}

func TestRB025_BcryptPassword_Safe(t *testing.T) {
	content := `digest = BCrypt::Password.create(password)`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-025")
}
