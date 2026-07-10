package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — AEAD authenticated decryption sanitizers (CWE-345 / CWE-502)
// =========================================================================
//
// CryptoKit's AES.GCM.open(_:using:) and ChaChaPoly.open(_:using:) perform
// AEAD authenticated decryption — successful return cryptographically
// authenticates the ciphertext + nonce + tag against the symmetric key, so
// the plaintext is integrity-checked. We model these as sanitizers that
// neutralise SnkDeserialize and SnkTrustBoundary on data flowing OUT of
// the open() call.
//
// Tests use function-parameter sources (default-tainted by the walker) so
// the verification chain is exercised end-to-end without depending on
// language-specific subscript-source propagation quirks.

// Negative baseline: tainted ciphertext flows directly to JSONSerialization
// .jsonObject(with:) (a SnkDeserialize sink). Without the AEAD step, the
// SnkDeserialize flow MUST be reported.
func TestSwift_AESGCM_Open_Negative_NoSanitizer(t *testing.T) {
	code := `
import Foundation

func handler(input: Data) throws {
    _ = try JSONSerialization.jsonObject(with: input)
}
`
	flows := Analyze(code, "/app/AeadNeg.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow when input reaches JSONSerialization.jsonObject without AEAD authentication")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Positive: tainted ciphertext is opened by AES.GCM.open() before reaching
// JSONSerialization.jsonObject. The AEAD sanitizer must cancel the
// SnkDeserialize flow on the resulting plaintext.
func TestSwift_CryptoKit_AESGCM_Open_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import CryptoKit

func handler(input: Data, key: SymmetricKey) throws {
    let sealedBox = try AES.GCM.SealedBox(combined: input)
    let plaintext = try AES.GCM.open(sealedBox, using: key)
    _ = try JSONSerialization.jsonObject(with: plaintext)
}
`
	flows := Analyze(code, "/app/AeadGcm.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when ciphertext is authenticated via AES.GCM.open(): %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Positive: ChaChaPoly.open() — same AEAD authenticity guarantee as AES-GCM.
func TestSwift_CryptoKit_ChaChaPoly_Open_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import CryptoKit

func handler(input: Data, key: SymmetricKey) throws {
    let sealedBox = try ChaChaPoly.SealedBox(combined: input)
    let plaintext = try ChaChaPoly.open(sealedBox, using: key)
    _ = try JSONSerialization.jsonObject(with: plaintext)
}
`
	flows := Analyze(code, "/app/AeadChaCha.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when ciphertext is authenticated via ChaChaPoly.open(): %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Over-broadness regression: the AES.GCM.open sanitizer must NOT neutralise
// injection categories (SQL, Command, XSS). AEAD authenticates origin — it
// does not make the plaintext syntactically safe. Tainted plaintext that
// reaches a SQL sink must still produce a SnkSQLQuery flow.
func TestSwift_AESGCM_Open_DoesNotSanitize_SQLInjection(t *testing.T) {
	code := `
import Foundation
import CryptoKit

func handler(input: Data, key: SymmetricKey, conn: PostgresConnection) throws {
    let sealedBox = try AES.GCM.SealedBox(combined: input)
    let plaintext = try AES.GCM.open(sealedBox, using: key)
    let str = String(data: plaintext, encoding: .utf8)!
    _ = conn.simpleQuery("SELECT * FROM users WHERE name = '" + str + "'")
}
`
	flows := Analyze(code, "/app/AeadSql.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow — AEAD authentication does not neutralise SQL injection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — JOSESwift JWS authenticated validation (CWE-347)
// =========================================================================

// Negative baseline: tainted JWT token flows directly to a SnkCrypto sink
// (Auth0 JWTDecode.swift, which never verifies signatures). Without JWS
// validation, the SnkCrypto flow MUST be reported.
func TestSwift_JOSESwift_JWS_Validate_Negative_NoSanitizer(t *testing.T) {
	code := `
import JWTDecode

func handler(input: String) throws {
    _ = try JWTDecode.decode(jwt: input)
}
`
	flows := Analyze(code, "/app/JoseNeg.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow when token reaches JWTDecode.decode without signature validation")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: JOSESwift jws.validate(with: publicKey) performs full cryptographic
// signature verification. After validation, the payload is authenticated
// and a downstream JWTDecode.decode call must NOT report SnkCrypto.
func TestSwift_JOSESwift_JWS_Validate_Sanitized(t *testing.T) {
	code := `
import JOSESwift
import JWTDecode

func handler(input: String, publicKey: SecKey) throws {
    let jws = try JWS(compactSerialization: input)
    let validated = try jws.validate(with: publicKey)
    let payload = String(data: validated.payload.data(), encoding: .utf8)!
    _ = try JWTDecode.decode(jwt: payload)
}
`
	flows := Analyze(code, "/app/JoseSwiftValidate.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("expected NO SnkCrypto flow when JWS is authenticated via jws.validate(with:): %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
