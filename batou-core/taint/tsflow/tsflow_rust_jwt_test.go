package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- jsonwebtoken::dangerous::insecure_decode (CWE-345) ---

func TestRust_JWT_DangerousInsecureDecode(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let token = env::var("JWT_TOKEN").unwrap();
    let claims: TokenData<Claims> = jsonwebtoken::dangerous::insecure_decode(&token).unwrap();
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for env::var -> jsonwebtoken::dangerous::insecure_decode")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Legacy top-level form used prior to the `dangerous` submodule split.
func TestRust_JWT_DangerousInsecureDecode_Legacy(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let token = env::var("JWT_TOKEN").unwrap();
    let claims: TokenData<Claims> = jsonwebtoken::dangerous_insecure_decode(&token).unwrap();
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for env::var -> jsonwebtoken::dangerous_insecure_decode")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- jsonwebtoken::dangerous::insecure_decode_with_validation (CWE-345) ---

func TestRust_JWT_DangerousInsecureDecodeWithValidation(t *testing.T) {
	code := `
use std::env;
use jsonwebtoken::Validation;

fn handle() {
    let token = env::var("JWT_TOKEN").unwrap();
    let validation = Validation::default();
    let claims: TokenData<Claims> = jsonwebtoken::dangerous::insecure_decode_with_validation(&token, &validation).unwrap();
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for env::var -> dangerous::insecure_decode_with_validation")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- jsonwebtoken::decode_header (CWE-345) ---

func TestRust_JWT_DecodeHeader(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let token = env::var("JWT_TOKEN").unwrap();
    let header = jsonwebtoken::decode_header(&token).unwrap();
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for env::var -> jsonwebtoken::decode_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe: jsonwebtoken::decode should not flag any JWT-bypass sink ---

// We use the qualified form `jsonwebtoken::decode(...)` (no turbofish) so the
// call is matched by the matcher and none of the three bypass sinks fire.
func TestRust_JWT_SafeDecode_NoFlow(t *testing.T) {
	code := `
use std::env;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

fn handle() {
    let token = env::var("JWT_TOKEN").unwrap();
    let validation = Validation::new(Algorithm::HS256);
    let key = DecodingKey::from_secret(b"secret");
    let claims = jsonwebtoken::decode(&token, &key, &validation).unwrap();
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	for _, f := range flows {
		switch f.Sink.ID {
		case "rust.jsonwebtoken.dangerous_insecure_decode",
			"rust.jsonwebtoken.dangerous_insecure_decode_with_validation",
			"rust.jsonwebtoken.decode_header":
			t.Errorf("unexpected JWT bypass flow for safe jsonwebtoken::decode: sink=%s", f.Sink.ID)
		}
	}
}
