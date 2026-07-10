package tsflow

// Zig does not have a tree-sitter grammar registered in ast/languages.go,
// so tsflow.Analyze falls through to the regex-based taint.Analyze engine.
// These tests verify the regex engine can detect:
//   - zip-slip (CWE-22) via std.zip.extract
//   - weak HMAC (CWE-328) via std.crypto.auth.hmac.HmacMd5/HmacSha1 and
//     the generic Hmac() constructor wrapping a weak hash.

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Zig — Zip slip via std.zip.extract (CWE-22)
// =========================================================================

func TestZig_ZipSlip_StdZipExtract_Httpz(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request) !void {
    const body = try req.body();
    var fbs = std.io.fixedBufferStream(body);
    var fr = fbs.reader();
    try std.zip.extract(std.fs.cwd(), &fr, .{});
}
`
	flows := taint.Analyze(code, "/app/upload.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected zip-slip flow for httpz body -> std.zip.extract")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ZipSlip_StdZipExtract_Zap(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) !void {
    const data = request.body();
    var fbs = std.io.fixedBufferStream(data);
    var fr = fbs.reader();
    try std.zip.extract(std.fs.cwd(), &fr, .{ .allow_backslashes = true });
}
`
	flows := taint.Analyze(code, "/app/zip_handler.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected zip-slip flow for zap body -> std.zip.extract")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Weak HMAC (CWE-328)
// =========================================================================

func TestZig_WeakHmac_HmacMd5(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn signRequest(req: *httpz.Request) !void {
    const body = try req.body();
    var out: [16]u8 = undefined;
    const key = "shared-secret";
    std.crypto.auth.hmac.HmacMd5.create(&out, body, key);
}
`
	flows := taint.Analyze(code, "/app/sign.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-HMAC flow for httpz body -> std.crypto.auth.hmac.HmacMd5")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_WeakHmac_HmacSha1(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn signRequest(req: *httpz.Request) !void {
    const payload = try req.body();
    var out: [20]u8 = undefined;
    const key = "shared-secret";
    std.crypto.auth.hmac.HmacSha1.create(&out, payload, key);
}
`
	flows := taint.Analyze(code, "/app/sign_sha1.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-HMAC flow for httpz body -> std.crypto.auth.hmac.HmacSha1")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_WeakHmac_GenericHmacConstructor(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn signRequest(req: *httpz.Request) !void {
    const body = try req.body();
    var out: [16]u8 = undefined;
    std.crypto.auth.hmac.Hmac(std.crypto.hash.Md5).create(&out, body, "key");
}
`
	flows := taint.Analyze(code, "/app/sign_generic.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-HMAC flow for httpz body -> generic Hmac(std.crypto.hash.Md5)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test — using HmacSha256 (a strong HMAC) should NOT trigger the
// weak-HMAC sink. Verifies the new patterns don't over-match SHA-2 variants.
func TestZig_WeakHmac_SafeSha256_NoFlow(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn signRequest(req: *httpz.Request) !void {
    const body = try req.body();
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, body, "key");
}
`
	flows := taint.Analyze(code, "/app/sign_safe.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("unexpected weak-HMAC flow for HmacSha256 (should be safe): sink %s", f.Sink.ID)
		}
	}
}
