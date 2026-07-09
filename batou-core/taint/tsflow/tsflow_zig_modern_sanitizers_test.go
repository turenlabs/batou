package tsflow

// Tests for the modern-crypto / validation sanitizers added to
// zig_sanitizers.go: SHA-3 family, HMAC-SHA256/512, HKDF, scrypt, PBKDF2,
// timingSafeEql, fs.path.isAbsolute, json.parseFromSlice, fmtSliceHexLower,
// utf8ValidCodepoint.
//
// Zig has no tree-sitter grammar registered, so taint.Analyze falls
// through to the regex-based engine and exercises the catalog patterns
// directly. Each "Sanitized_*" test relies on the sanitizer breaking
// taint propagation between the source and the sink.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Zig — Path traversal: fs.path.isAbsolute as path-validation sanitizer
// =========================================================================

func TestZig_FileRead_Sanitized_IsAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const filename = request.getParamSlice("file");
    const checked = std.fs.path.isAbsolute(filename);
    const file = std.fs.openFileAbsolute(checked, .{});
}
`
	flows := taint.Analyze(code, "/app/serve.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO FileRead flow when std.fs.path.isAbsolute validates the path")
		}
	}
}

// =========================================================================
// Zig — XSS: fmtSliceHexLower as HTML-safe output encoding
// =========================================================================

func TestZig_XSS_Sanitized_FmtSliceHexLower(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    const encoded = std.fmt.fmtSliceHexLower(user_input);
    request.sendBody(encoded);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when std.fmt.fmtSliceHexLower encodes the bytes")
		}
	}
}

// =========================================================================
// Zig — XSS: utf8ValidCodepoint as input-validation sanitizer
// =========================================================================

func TestZig_XSS_Sanitized_Utf8ValidCodepoint(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    const validated = std.unicode.utf8ValidCodepoint(user_input);
    request.sendBody(validated);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when std.unicode.utf8ValidCodepoint validates the input")
		}
	}
}

// =========================================================================
// Zig — Crypto sanitizers: SHA-3 family (FIPS 202)
// =========================================================================

func TestZig_Crypto_Sanitized_Sha3_256(t *testing.T) {
	code := `
const std = @import("std");

fn hash_data(data: []const u8) void {
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(data);
    const digest = hasher.finalResult();
}
`
	flows := taint.Analyze(code, "/app/hash.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when SHA3-256 is used")
		}
	}
}

func TestZig_Crypto_Sanitized_Sha3_512(t *testing.T) {
	code := `
const std = @import("std");

fn hash_data(data: []const u8) void {
    var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
    hasher.update(data);
    const digest = hasher.finalResult();
}
`
	flows := taint.Analyze(code, "/app/hash.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when SHA3-512 is used")
		}
	}
}

// =========================================================================
// Zig — Crypto sanitizers: HMAC-SHA256/512 (modern MAC)
// =========================================================================

func TestZig_Crypto_Sanitized_HmacSha256(t *testing.T) {
	code := `
const std = @import("std");

fn mac(key: []const u8, msg: []const u8) void {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, msg, key);
}
`
	flows := taint.Analyze(code, "/app/mac.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when HmacSha256 is used")
		}
	}
}

func TestZig_Crypto_Sanitized_HmacSha512(t *testing.T) {
	code := `
const std = @import("std");

fn mac(key: []const u8, msg: []const u8) void {
    var out: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&out, msg, key);
}
`
	flows := taint.Analyze(code, "/app/mac.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when HmacSha512 is used")
		}
	}
}

// =========================================================================
// Zig — Crypto sanitizers: HKDF key derivation (RFC 5869)
// =========================================================================

func TestZig_Crypto_Sanitized_HkdfSha256(t *testing.T) {
	code := `
const std = @import("std");

fn derive(salt: []const u8, ikm: []const u8) void {
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(salt, ikm);
    var out: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&out, "info", prk);
}
`
	flows := taint.Analyze(code, "/app/kdf.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when HkdfSha256 is used")
		}
	}
}

// =========================================================================
// Zig — Crypto sanitizers: scrypt + PBKDF2 password hashing
// =========================================================================

func TestZig_Crypto_Sanitized_Scrypt(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn register(request: zap.Request) void {
    const password = request.getParamSlice("password");
    const hash = std.crypto.pwhash.scrypt.strHash(password, .{}, salt);
    store_hash(hash);
}
`
	flows := taint.Analyze(code, "/app/auth.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when scrypt password hashing is used")
		}
	}
}

func TestZig_Crypto_Sanitized_Pbkdf2(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn register(request: zap.Request) void {
    const password = request.getParamSlice("password");
    var dk: [32]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&dk, password, salt, 100000, std.crypto.auth.hmac.sha2.HmacSha256);
    store_key(dk);
}
`
	flows := taint.Analyze(code, "/app/auth.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when PBKDF2 password hashing is used")
		}
	}
}

// =========================================================================
// Zig — Crypto sanitizers: timingSafeEql (CWE-208 timing-attack mitigation)
// =========================================================================

func TestZig_Crypto_Sanitized_TimingSafeEql(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn verify_token(request: zap.Request) bool {
    const candidate = request.getParamSlice("token");
    const expected = load_secret_token();
    return std.crypto.utils.timingSafeEql([32]u8, candidate, expected);
}
`
	flows := taint.Analyze(code, "/app/auth.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when timingSafeEql is used for token comparison")
		}
	}
}
