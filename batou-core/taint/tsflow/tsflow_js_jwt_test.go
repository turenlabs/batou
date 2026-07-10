package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// JavaScript — jose JWT signature-verification bypass (CWE-347)
// =========================================================================
// jose (~27M weekly) exposes decode utilities that do NOT verify the JWS
// signature. Using their output as authentication state lets an attacker
// forge tokens — library docs explicitly direct callers to jwtVerify.

func TestJS_Jose_DecodeJwt_NoVerify(t *testing.T) {
	code := `
const { decodeJwt } = require('jose');

function handler(req, res) {
    const token = req.headers.authorization.replace('Bearer ', '');
    const claims = decodeJwt(token);
    if (claims.role === 'admin') {
        res.send('secret');
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for req.headers -> jose.decodeJwt")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Jose_DecodeProtectedHeader_NoVerify(t *testing.T) {
	code := `
const { decodeProtectedHeader } = require('jose');

function handler(req, res) {
    const token = req.body.token;
    const header = decodeProtectedHeader(token);
    const kid = header.kid;
    res.send('kid=' + kid);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for req.body -> jose.decodeProtectedHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Jose_UnsecuredJWT_Decode(t *testing.T) {
	code := `
const { UnsecuredJWT } = require('jose');

function handler(req, res) {
    const token = req.query.t;
    const result = UnsecuredJWT.decode(token, { issuer: 'me' });
    res.send(result.payload);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for req.query -> UnsecuredJWT.decode")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe path — jose.jwtVerify sanitizes the flow (signature + claims validated).
func TestJS_Jose_JwtVerify_Sanitizes(t *testing.T) {
	code := `
const { jwtVerify } = require('jose');

async function handler(req, res) {
    const token = req.headers.authorization.replace('Bearer ', '');
    const { payload } = await jwtVerify(token, secretKey);
    res.send(payload.sub);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	// jwtVerify is a sanitizer for SnkTrustBoundary/SnkDeserialize but not SnkCrypto;
	// however, there's no decode() sink in this flow, so no SnkCrypto flow should fire.
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && (f.Sink.ID == "js.jose.decodejwt" ||
			f.Sink.ID == "js.jose.decodeprotectedheader" || f.Sink.ID == "js.jose.unsecuredjwt.decode") {
			t.Errorf("unexpected jose-decode sink hit for jwtVerify flow: sink=%s", f.Sink.ID)
		}
	}
}
