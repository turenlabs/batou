package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — Modern password hashing / KDF sanitizers (CWE-916, CWE-327)
//
// Each test verifies a sanitizer added in ruby_sanitizers.go neutralizes a
// taint flow from user-controlled input to a SnkCrypto sink. We use
// Random.rand(...) (matches ruby.crypto.random.new, ObjectType "Random",
// DangerousArgs [-1]) because it is the SnkCrypto sink that fires reliably
// under tsflow for Ruby — Digest::MD5/SHA1 catalog entries are indexed under
// MethodName "MD5"/"SHA1" so they only fire via the Layer 1 regex fallback,
// not the tsflow matcher.
//
// Pattern:
//   source: params[:password]              (SrcUserInput)
//   sanitizer: hashed = <kdf>(password)    (Neutralizes SnkCrypto)
//   sink: Random.rand(hashed)              (SnkCrypto, ruby.crypto.random.new)
// =========================================================================

// argon2 gem (https://github.com/technion/ruby-argon2) — Argon2::Password.create
func TestRuby_Sanitizer_Argon2PasswordCreate(t *testing.T) {
	code := `
require 'argon2'
def store(params)
  password = params[:password]
  hashed = Argon2::Password.create(password)
  Random.rand(hashed)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Argon2::Password.create should neutralize SnkCrypto flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// argon2 gem — Argon2::Password.verify_password (constant-time verification)
func TestRuby_Sanitizer_Argon2VerifyPassword(t *testing.T) {
	code := `
require 'argon2'
def login(params)
  password = params[:password]
  ok = Argon2::Password.verify_password(password, stored_hash)
  Random.rand(ok.to_s)
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Argon2::Password.verify_password should neutralize SnkCrypto flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// scrypt gem (https://github.com/pbhogan/scrypt) — SCrypt::Password.create
func TestRuby_Sanitizer_SCryptPasswordCreate(t *testing.T) {
	code := `
require 'scrypt'
def store(params)
  password = params[:password]
  hashed = SCrypt::Password.create(password)
  Random.rand(hashed)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("SCrypt::Password.create should neutralize SnkCrypto flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// OpenSSL::KDF.pbkdf2_hmac — Ruby stdlib (2.5+) modern PBKDF2 API
func TestRuby_Sanitizer_OpenSSLKDFPbkdf2Hmac(t *testing.T) {
	code := `
require 'openssl'
def derive(params)
  password = params[:password]
  key = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: 600000, length: 32, hash: 'sha256')
  Random.rand(key)
end
`
	flows := Analyze(code, "/app/lib/key_derivation.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("OpenSSL::KDF.pbkdf2_hmac should neutralize SnkCrypto flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// OpenSSL::PKCS5.pbkdf2_hmac — legacy PBKDF2 API (still widely used)
func TestRuby_Sanitizer_OpenSSLPKCS5Pbkdf2Hmac(t *testing.T) {
	code := `
require 'openssl'
def derive(params)
  password = params[:password]
  key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 100000, 32, OpenSSL::Digest::SHA256.new)
  Random.rand(key)
end
`
	flows := Analyze(code, "/app/lib/key_derivation.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("OpenSSL::PKCS5.pbkdf2_hmac should neutralize SnkCrypto flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// rbnacl gem (libsodium) — RbNaCl::PasswordHash.argon2id
func TestRuby_Sanitizer_RbNaClArgon2id(t *testing.T) {
	code := `
require 'rbnacl'
def store(params)
  password = params[:password]
  hashed = RbNaCl::PasswordHash.argon2id(password, 5, 7_864_320, 32, salt)
  Random.rand(hashed)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("RbNaCl::PasswordHash.argon2id should neutralize SnkCrypto flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// =========================================================================
// Negative test — without a sanitizer the SnkCrypto flow MUST fire.
// Confirms the test scaffolding actually detects the unsanitized case, so the
// positive tests above cannot pass vacuously (no source-to-sink flow).
// =========================================================================

func TestRuby_Sanitizer_Unsanitized_PasswordToRandom(t *testing.T) {
	code := `
def store(params)
  password = params[:password]
  Random.rand(password)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for unsanitized params -> Random.rand(password)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
