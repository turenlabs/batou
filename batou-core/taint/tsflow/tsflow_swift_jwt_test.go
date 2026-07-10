package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — JWT signature-bypass tests (CWE-347)
// =========================================================================

// SwiftJWT (Kitura) JWT.decode parses a JWT without verifying the signature.
// A tainted token flowing into JWT.decode lets an attacker forge arbitrary
// claims.
func TestSwift_JWT_Kitura_Decode_Unverified(t *testing.T) {
	code := `
import SwiftJWT

func handler(req: Request) throws {
    let token = req.query["jwt"]
    let jwt = try JWT.decode(token)
    _ = jwt
}
`
	flows := Analyze(code, "/app/JwtHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for req.query -> JWT.decode()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Auth0 JWTDecode.swift decode(jwt:) is a client-side-only helper that never
// verifies signatures. Trusting its output server-side is CWE-347. The catalog
// matches the module-qualified form `JWTDecode.decode(jwt: token)`.
func TestSwift_JWT_Auth0_Decode_Unverified(t *testing.T) {
	code := `
import JWTDecode

func handler(req: Request) throws {
    let token = req.query["jwt"]
    let jwt = try JWTDecode.decode(jwt: token)
    _ = jwt
}
`
	flows := Analyze(code, "/app/Auth0Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for req.query -> JWTDecode.decode(jwt:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: SwiftJWT JWT.verify(token, using: verifier) performs cryptographic
// signature verification. The sanitizer neutralizes SnkCrypto so no flow is
// reported for a token that reaches JWT.verify.
func TestSwift_JWT_Kitura_Verify_Sanitized(t *testing.T) {
	code := `
import SwiftJWT

func handler(req: Request) throws {
    let token = req.query["jwt"]
    let verifier = JWTVerifier.hs256(key: "secret".data(using: .utf8)!)
    let ok = JWT.verify(token, using: verifier)
    _ = ok
}
`
	flows := Analyze(code, "/app/JwtVerify.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("expected NO SnkCrypto flow when JWT.verify(using:) is used: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
