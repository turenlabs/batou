package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Zig — Path traversal FileRead: unsanitized vs sanitized (CWE-22)
// =========================================================================

func TestZig_FileRead_Unsanitized(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const filename = request.getParamSlice("file");
    const file = std.fs.openFileAbsolute(filename, .{});
}
`
	flows := taint.Analyze(code, "/app/serve.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow when user input goes directly to openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_FileRead_Sanitized_PathNormalize(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const filename = request.getParamSlice("file");
    const safe = std.fs.path.normalize(filename);
    const file = std.fs.openFileAbsolute(safe, .{});
}
`
	flows := taint.Analyze(code, "/app/serve.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO FileRead flow when std.fs.path.normalize is used")
		}
	}
}

func TestZig_FileRead_Sanitized_Basename(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const filename = request.getParamSlice("file");
    const safe = std.fs.path.basename(filename);
    const file = std.fs.openFileAbsolute(safe, .{});
}
`
	flows := taint.Analyze(code, "/app/serve.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO FileRead flow when std.fs.path.basename is used")
		}
	}
}

func TestZig_FileRead_Sanitized_RealpathAlloc(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const filename = request.getParamSlice("file");
    const safe = dir.realpathAlloc(allocator, filename);
    const file = std.fs.openFileAbsolute(safe, .{});
}
`
	flows := taint.Analyze(code, "/app/serve.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO FileRead flow when Dir.realpathAlloc is used")
		}
	}
}

// =========================================================================
// Zig — Base64 encoding sanitizer (SnkHTMLOutput)
// =========================================================================

func TestZig_XSS_Unsanitized_SendBody(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    request.sendBody(user_input);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow when user input goes directly to sendBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_XSS_Sanitized_Base64Encode(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    const encoded = std.base64.standard.Encoder.encode(buf, user_input);
    request.sendBody(encoded);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when std.base64 encoding is used")
		}
	}
}

// =========================================================================
// Zig — JSON stringify sanitizer (SnkHTMLOutput, SnkLog)
// =========================================================================

func TestZig_XSS_Sanitized_JsonStringify(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    const json_output = std.json.stringify(user_input, .{}, writer);
    request.sendBody(json_output);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when std.json.stringify is used")
		}
	}
}

func TestZig_Log_Sanitized_JsonStringifyAlloc(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    const safe = std.json.stringifyAlloc(allocator, user_input, .{});
    std.log.info("{s}", .{safe});
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when std.json.stringifyAlloc is used")
		}
	}
}

// =========================================================================
// Zig — Crypto sanitizers: AEAD, password hashing, secure hashes
// =========================================================================

func TestZig_Crypto_Sanitized_AesGcm(t *testing.T) {
	code := `
const std = @import("std");

fn encrypt(data: []const u8) void {
    const key = get_key();
    const aead = std.crypto.aead.aes_gcm.Aes256Gcm;
    aead.encrypt(ciphertext, tag, data, null, key, nonce);
}
`
	flows := taint.Analyze(code, "/app/crypto.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when AES-GCM is used")
		}
	}
}

func TestZig_Crypto_Sanitized_ChaCha20Poly1305(t *testing.T) {
	code := `
const std = @import("std");

fn encrypt(data: []const u8) void {
    const key = get_key();
    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    aead.encrypt(ciphertext, tag, data, null, key, nonce);
}
`
	flows := taint.Analyze(code, "/app/crypto.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when ChaCha20-Poly1305 is used")
		}
	}
}

func TestZig_Crypto_Sanitized_Argon2(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn register(request: zap.Request) void {
    const password = request.getParamSlice("password");
    const hash = std.crypto.pwhash.argon2.strHash(password, .{}, salt);
    store_hash(hash);
}
`
	flows := taint.Analyze(code, "/app/auth.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when Argon2 password hashing is used")
		}
	}
}

func TestZig_Crypto_Sanitized_Bcrypt(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn register(request: zap.Request) void {
    const password = request.getParamSlice("password");
    const hash = std.crypto.pwhash.bcrypt.hashPassword(password, salt, .{});
    store_hash(hash);
}
`
	flows := taint.Analyze(code, "/app/auth.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when bcrypt is used")
		}
	}
}

func TestZig_Crypto_Sanitized_Sha384(t *testing.T) {
	code := `
const std = @import("std");

fn hash_data(data: []const u8) void {
    var hasher = std.crypto.hash.sha2.Sha384.init(.{});
    hasher.update(data);
    const digest = hasher.finalResult();
}
`
	flows := taint.Analyze(code, "/app/hash.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when SHA-384 is used")
		}
	}
}

func TestZig_Crypto_Sanitized_Sha512(t *testing.T) {
	code := `
const std = @import("std");

fn hash_data(data: []const u8) void {
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update(data);
    const digest = hasher.finalResult();
}
`
	flows := taint.Analyze(code, "/app/hash.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when SHA-512 is used")
		}
	}
}

// =========================================================================
// Zig — SSRF sanitizers: IP validation, scheme checks, blocklist (CWE-918)
// =========================================================================

func TestZig_SSRF_Unsanitized_HttpClientFetch(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn proxy(request: zap.Request) void {
    const target_url = request.getParamSlice("url");
    var client = std.http.Client{ .allocator = allocator };
    const result = client.fetch(target_url, .{});
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow when user input goes directly to http.Client.fetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_SSRF_Sanitized_AddressParseIp(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn proxy(request: zap.Request) void {
    const host = request.getParamSlice("host");
    const addr = std.net.Address.parseIp(host, 8080) catch return;
    var client = std.http.Client{ .allocator = allocator };
    const result = client.fetch(addr, .{});
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when std.net.Address.parseIp is used for validation")
		}
	}
}

func TestZig_SSRF_Sanitized_Ip4AddressParse(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn proxy(request: zap.Request) void {
    const host = request.getParamSlice("host");
    const ip = std.net.Ip4Address.parse(host, 8080) catch return;
    var client = std.http.Client{ .allocator = allocator };
    const result = client.fetch(ip, .{});
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when std.net.Ip4Address.parse validates the IP")
		}
	}
}

func TestZig_SSRF_Sanitized_EqlIgnoreCase(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn proxy(request: zap.Request) void {
    const target_url = request.getParamSlice("url");
    const validated = std.ascii.eqlIgnoreCase(target_url, "https://allowed.example.com");
    var client = std.http.Client{ .allocator = allocator };
    const result = client.fetch(validated, .{});
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when std.ascii.eqlIgnoreCase validates the URL")
		}
	}
}

func TestZig_SSRF_Sanitized_MemIndexOf(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn proxy(request: zap.Request) void {
    const target_url = request.getParamSlice("url");
    const checked = std.mem.indexOf(u8, target_url, "internal");
    var client = std.http.Client{ .allocator = allocator };
    const result = client.fetch(checked, .{});
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when std.mem.indexOf is used for blocklist checking")
		}
	}
}
