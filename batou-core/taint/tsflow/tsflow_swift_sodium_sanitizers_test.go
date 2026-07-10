package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — swift-sodium AEAD + Ed25519 signature sanitizer tests
// (CWE-345 / CWE-347 / CWE-502)
// =========================================================================
//
// swift-sodium (github.com/jedisct1/swift-sodium) wraps libsodium for Swift.
// Its SecretBox.open / Box.open / Aead.*.decrypt / Sign.open APIs all return
// Bytes? where nil indicates MAC or signature verification failure — i.e.
// successful return cryptographically authenticates the input. We model
// these as return-value sanitizers neutralising SnkDeserialize and
// SnkTrustBoundary on the resulting plaintext.
//
// Tests use function-parameter sources (`input: Data`) which the walker
// auto-taints via the isInputParamName allowlist. The negative baseline
// confirms a SnkDeserialize flow without any sodium step; each positive
// test then adds the sanitizer and asserts the SnkDeserialize flow is
// suppressed. The over-broadness regression confirms SnkSQLQuery flows
// are NOT neutralised — AEAD/signature schemes authenticate origin but
// do not make plaintext syntactically safe.

// Negative baseline: tainted ciphertext flows directly into
// JSONSerialization.jsonObject(with:) (a SnkDeserialize sink). Without any
// sodium authentication step, the SnkDeserialize flow MUST be reported.
func TestSwift_Sodium_Negative_NoSanitizer(t *testing.T) {
	code := `
import Foundation

func handler(input: Data) throws {
    _ = try JSONSerialization.jsonObject(with: input)
}
`
	flows := Analyze(code, "/app/SodiumNeg.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow when input reaches JSONSerialization.jsonObject without sodium authentication")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Positive: sodium.secretBox.open() XSalsa20-Poly1305 AEAD authenticates the
// ciphertext before it reaches a deserialization sink. The sanitizer must
// cancel the SnkDeserialize flow on the resulting plaintext.
func TestSwift_Sodium_SecretBox_Open_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import Sodium

func handler(input: Data) throws {
    let sodium = Sodium()
    let key = sodium.secretBox.key()
    let plaintext = sodium.secretBox.open(authenticatedCipherText: input.bytes, secretKey: key)
    _ = try JSONSerialization.jsonObject(with: plaintext)
}
`
	flows := Analyze(code, "/app/SodiumSecretBox.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when ciphertext is authenticated via sodium.secretBox.open(): %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Positive: sodium.box.open() Curve25519 + XSalsa20-Poly1305 public-key AEAD.
// The senderPublicKey + recipientSecretKey pair derives the shared secret
// via X25519 ECDH; successful Poly1305 MAC verification authenticates both
// origin and integrity.
func TestSwift_Sodium_Box_Open_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import Sodium

func handler(input: Data) throws {
    let sodium = Sodium()
    let kp = sodium.box.keyPair()
    let plaintext = sodium.box.open(authenticatedCipherText: input.bytes, senderPublicKey: kp.publicKey, recipientSecretKey: kp.secretKey)
    _ = try JSONSerialization.jsonObject(with: plaintext)
}
`
	flows := Analyze(code, "/app/SodiumBox.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when ciphertext is authenticated via sodium.box.open(): %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Positive: sodium.aead.xchacha20poly1305ietf.decrypt() — XChaCha20-Poly1305
// IETF AEAD with the 24-byte XChaCha20 nonce.
func TestSwift_Sodium_Aead_XChaCha20_Decrypt_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import Sodium

func handler(input: Data) throws {
    let sodium = Sodium()
    let key = sodium.aead.xchacha20poly1305ietf.key()
    let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: input.bytes, secretKey: key)
    _ = try JSONSerialization.jsonObject(with: plaintext)
}
`
	flows := Analyze(code, "/app/SodiumXChaCha.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when ciphertext is authenticated via sodium.aead.xchacha20poly1305ietf.decrypt(): %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Positive: sodium.aead.chacha20poly1305ietf.decrypt() — RFC 7539 variant
// with the shorter 12-byte ChaCha20 nonce.
func TestSwift_Sodium_Aead_ChaCha20_Decrypt_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import Sodium

func handler(input: Data) throws {
    let sodium = Sodium()
    let key = sodium.aead.chacha20poly1305ietf.key()
    let plaintext = sodium.aead.chacha20poly1305ietf.decrypt(authenticatedCipherText: input.bytes, secretKey: key)
    _ = try JSONSerialization.jsonObject(with: plaintext)
}
`
	flows := Analyze(code, "/app/SodiumChaCha.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when ciphertext is authenticated via sodium.aead.chacha20poly1305ietf.decrypt(): %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Positive: sodium.sign.open() Ed25519 signed-message verification. Returns
// the original message bytes only when the attached Ed25519 signature
// validates against the public key.
func TestSwift_Sodium_Sign_Open_Sanitizes_Deserialize(t *testing.T) {
	code := `
import Foundation
import Sodium

func handler(input: Data) throws {
    let sodium = Sodium()
    let kp = sodium.sign.keyPair()
    let unsigned = sodium.sign.open(signedMessage: input.bytes, publicKey: kp.publicKey)
    _ = try JSONSerialization.jsonObject(with: unsigned)
}
`
	flows := Analyze(code, "/app/SodiumSign.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("expected NO SnkDeserialize flow when signed message is verified via sodium.sign.open(): %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Over-broadness regression: the sodium AEAD/signature sanitizers must NOT
// neutralise injection categories. AEAD authenticates origin — it does not
// make the plaintext syntactically safe for SQL/Command/HTML contexts.
// A plaintext flowing into SQLite execute() must still produce a SnkSQLQuery
// flow even after sodium.secretBox.open() authentication.
func TestSwift_Sodium_SecretBox_Open_Does_Not_Sanitize_SQLi(t *testing.T) {
	code := `
import Foundation
import Sodium
import SQLite

func handler(input: Data, db: Connection) throws {
    let sodium = Sodium()
    let key = sodium.secretBox.key()
    let plaintext = sodium.secretBox.open(authenticatedCipherText: input.bytes, secretKey: key)
    let sql = "SELECT * FROM users WHERE name = '" + String(data: Data(plaintext!), encoding: .utf8)! + "'"
    _ = try db.execute(sql)
}
`
	flows := Analyze(code, "/app/SodiumSqliRegression.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow despite sodium.secretBox.open() — AEAD authenticates origin but does NOT make plaintext SQL-safe")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f, id: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
