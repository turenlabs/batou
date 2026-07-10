package tsflow

// Zig does not have a tree-sitter grammar registered in ast/languages.go,
// so tsflow.Analyze falls through to the regex-based taint.Analyze engine.
// These tests verify the regex engine can detect decompression-bomb (CWE-409)
// sinks via the std.compress.* catalog entries.

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Zig — Decompression bomb via std.compress.gzip.decompress (CWE-409)
// =========================================================================

func TestZig_DecompressionBomb_Gzip(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) !void {
    const body = request.body();
    var fbs = std.io.fixedBufferStream(body);
    var out = std.ArrayList(u8).init(allocator);
    try std.compress.gzip.decompress(fbs.reader(), out.writer());
}
`
	flows := taint.Analyze(code, "/app/upload.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected decompression-bomb flow for zap body -> std.compress.gzip.decompress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Streaming gzip decompressor over untrusted reader (CWE-409)
// =========================================================================

func TestZig_DecompressionBomb_GzipDecompressor(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request) !void {
    const payload = try req.body();
    var fbs = std.io.fixedBufferStream(payload);
    var dcp = std.compress.gzip.decompressor(fbs.reader());
    _ = try dcp.reader().readAllAlloc(allocator, 1024 * 1024 * 1024);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected decompression-bomb flow for httpz body -> std.compress.gzip.decompressor")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Decompression bomb via std.compress.zlib (CWE-409)
// =========================================================================

func TestZig_DecompressionBomb_Zlib(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) !void {
    const data = request.body();
    var fbs = std.io.fixedBufferStream(data);
    var out = std.ArrayList(u8).init(allocator);
    try std.compress.zlib.decompress(fbs.reader(), out.writer());
}
`
	flows := taint.Analyze(code, "/app/zlib_handler.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected decompression-bomb flow for zap body -> std.compress.zlib.decompress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Decompression bomb via std.compress.flate (CWE-409)
// =========================================================================

func TestZig_DecompressionBomb_Flate(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request) !void {
    const compressed = try req.body();
    var fbs = std.io.fixedBufferStream(compressed);
    var out = std.ArrayList(u8).init(allocator);
    try std.compress.flate.decompress(fbs.reader(), out.writer());
}
`
	flows := taint.Analyze(code, "/app/flate_handler.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected decompression-bomb flow for httpz body -> std.compress.flate.decompress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Decompression bomb via std.compress.zstandard (CWE-409)
// =========================================================================

func TestZig_DecompressionBomb_Zstandard(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) !void {
    const data = request.body();
    var fbs = std.io.fixedBufferStream(data);
    var out = std.ArrayList(u8).init(allocator);
    try std.compress.zstandard.decompress(fbs.reader(), out.writer());
}
`
	flows := taint.Analyze(code, "/app/zstd_handler.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected decompression-bomb flow for zap body -> std.compress.zstandard.decompress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Decompression bomb via std.compress.xz (CWE-409)
// =========================================================================

func TestZig_DecompressionBomb_Xz(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) !void {
    const data = request.body();
    var fbs = std.io.fixedBufferStream(data);
    var out = std.ArrayList(u8).init(allocator);
    try std.compress.xz.decompress(allocator, fbs.reader(), out.writer());
}
`
	flows := taint.Analyze(code, "/app/xz_handler.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected decompression-bomb flow for zap body -> std.compress.xz.decompress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
