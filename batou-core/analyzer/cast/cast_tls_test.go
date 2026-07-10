package cast

import "testing"

// --- BATOU-CAST-009: OpenSSL always-accept verify callback (CWE-295) ---

// TP: callback wired into SSL_CTX_set_verify that unconditionally returns 1.
func TestCAST008_AlwaysAcceptCallback(t *testing.T) {
	code := `
#include <openssl/ssl.h>
static int accept_all(int preverify_ok, X509_STORE_CTX *ctx) {
    return 1;
}
void setup(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, accept_all);
}
`
	if !hasRule(scanCpp(code), "BATOU-CAST-009") {
		t.Error("expected BATOU-CAST-009 for always-accept verify callback")
	}
}

// TP: SSL_set_verify (per-connection) variant.
func TestCAST008_AlwaysAcceptCallback_SSLSetVerify(t *testing.T) {
	code := `
static int cb(int ok, X509_STORE_CTX *c) {
    return (1);
}
void f(SSL *ssl) {
    SSL_set_verify(ssl, SSL_VERIFY_PEER, cb);
}
`
	if !hasRule(scanCpp(code), "BATOU-CAST-009") {
		t.Error("expected BATOU-CAST-009 for SSL_set_verify always-accept callback")
	}
}

// Safe: callback that actually propagates preverify_ok — must NOT fire.
func TestCAST008_Safe_PropagatesResult(t *testing.T) {
	code := `
static int real_cb(int preverify_ok, X509_STORE_CTX *ctx) {
    return preverify_ok;
}
void setup(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, real_cb);
}
`
	if hasRule(scanCpp(code), "BATOU-CAST-009") {
		t.Error("BATOU-CAST-009 false positive on callback that returns preverify_ok")
	}
}

// Safe: callback that inspects the chain (has a conditional) — must NOT fire,
// even though one branch returns 1.
func TestCAST008_Safe_ConditionalCallback(t *testing.T) {
	code := `
static int cb(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        return 0;
    }
    return 1;
}
void setup(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cb);
}
`
	if hasRule(scanCpp(code), "BATOU-CAST-009") {
		t.Error("BATOU-CAST-009 false positive on callback with chain inspection")
	}
}

// Safe: a function that returns 1 but is NOT wired into set_verify — must NOT
// fire (no registration anchor).
func TestCAST008_Safe_UnregisteredReturnsOne(t *testing.T) {
	code := `
static int helper(int a, int b) {
    return 1;
}
int main() { return helper(1, 2); }
`
	if hasRule(scanCpp(code), "BATOU-CAST-009") {
		t.Error("BATOU-CAST-009 false positive on unregistered function returning 1")
	}
}
