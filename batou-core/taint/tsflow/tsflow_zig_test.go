package tsflow

// Zig does not have a tree-sitter grammar registered in ast/languages.go,
// so tsflow.Analyze falls through to the regex-based taint.Analyze engine.
// These tests verify the regex engine can detect taint flows using the
// Zig catalog entries. We call taint.Analyze directly.

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasZigTaintFlow(flows []taint.TaintFlow, sinkCategory taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == sinkCategory {
			return true
		}
	}
	return false
}

// =========================================================================
// Zig — HTTP header injection via zap setHeader (CWE-113)
// =========================================================================

func TestZig_HeaderInjection_ZapSetHeader(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_val = request.getParamSlice("redirect");
    request.setHeader("Location", user_val);
    request.sendBody("redirecting...");
}
`
	flows := taint.Analyze(code, "/app/server.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for zap getParamSlice -> setHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — XSS via zap sendJson (CWE-79)
// =========================================================================

func TestZig_XSS_ZapSendJson(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const user_input = request.getParamSlice("data");
    request.sendJson(user_input);
}
`
	flows := taint.Analyze(code, "/app/api.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for zap getParamSlice -> sendJson")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — SSRF via std.posix.connect (CWE-918)
// =========================================================================

func TestZig_SSRF_PosixConnect(t *testing.T) {
	code := `
const std = @import("std");

pub fn fetch_url(request: zap.Request) void {
    const host = request.getParamSlice("host");
    const addr = std.net.Address.resolveIp(host, 8080);
    std.posix.connect(sock, addr);
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParamSlice -> posix.connect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — SSRF via std.posix.sendto (CWE-918)
// =========================================================================

func TestZig_SSRF_PosixSendto(t *testing.T) {
	code := `
const std = @import("std");

pub fn forward_data(request: zap.Request) void {
    const payload = request.getParamSlice("body");
    std.posix.sendto(sock, payload, 0, null, 0);
}
`
	flows := taint.Analyze(code, "/app/forward.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParamSlice -> posix.sendto")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — SSRF via std.net.tcpConnectToAddress (CWE-918)
// =========================================================================

func TestZig_SSRF_NetTcpConnectToAddress(t *testing.T) {
	code := `
const std = @import("std");

pub fn forward(request: zap.Request) !void {
    const host = request.getParamSlice("host");
    const addr = try std.net.Address.resolveIp(host, 8080);
    const stream = try std.net.tcpConnectToAddress(addr);
    _ = stream;
}
`
	flows := taint.Analyze(code, "/app/proxy.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for tainted host -> std.net.tcpConnectToAddress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — SSRF via std.net.getAddressList (CWE-918)
// =========================================================================

func TestZig_SSRF_NetGetAddressList(t *testing.T) {
	code := `
const std = @import("std");

pub fn lookup(request: zap.Request, allocator: std.mem.Allocator) !void {
    const hostname = request.getParamSlice("target");
    const list = try std.net.getAddressList(allocator, hostname, 80);
    _ = list;
}
`
	flows := taint.Analyze(code, "/app/dns.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for tainted hostname -> std.net.getAddressList")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Local SSRF via std.net.connectUnixSocket (CWE-918)
// =========================================================================

func TestZig_SSRF_NetConnectUnixSocket(t *testing.T) {
	code := `
const std = @import("std");

pub fn open_socket(request: zap.Request) !void {
    const sock_path = request.getParamSlice("path");
    const stream = try std.net.connectUnixSocket(sock_path);
    _ = stream;
}
`
	flows := taint.Analyze(code, "/app/local.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for tainted path -> std.net.connectUnixSocket")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.posix.open (CWE-22)
// =========================================================================

func TestZig_PathTraversal_PosixOpen(t *testing.T) {
	code := `
const std = @import("std");

pub fn read_file(request: zap.Request) void {
    const filename = request.getParamSlice("file");
    const fd = std.posix.open(filename, .{ .ACCMODE = .RDONLY }, 0);
}
`
	flows := taint.Analyze(code, "/app/files.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for getParamSlice -> posix.open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.posix.openat (CWE-22)
// =========================================================================

func TestZig_PathTraversal_PosixOpenat(t *testing.T) {
	code := `
const std = @import("std");

pub fn open_at_dir(request: zap.Request, dirfd: i32) void {
    const filename = request.getParamSlice("file");
    const fd = std.posix.openat(dirfd, filename, .{ .ACCMODE = .RDONLY }, 0);
}
`
	flows := taint.Analyze(code, "/app/openat.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for getParamSlice -> posix.openat")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Symlink disclosure via std.posix.readlink (CWE-22)
// =========================================================================

func TestZig_SymlinkDisclosure_PosixReadlink(t *testing.T) {
	code := `
const std = @import("std");

pub fn resolve_link(request: zap.Request, buf: []u8) void {
    const link_path = request.getParamSlice("path");
    _ = std.posix.readlink(link_path, buf) catch return;
}
`
	flows := taint.Analyze(code, "/app/readlink.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected symlink disclosure flow for getParamSlice -> posix.readlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Hard link attack via std.posix.link (CWE-59)
// =========================================================================

func TestZig_HardLinkAttack_PosixLink(t *testing.T) {
	code := `
const std = @import("std");

pub fn create_link(request: zap.Request) void {
    const target = request.getParamSlice("target");
    std.posix.link("/tmp/source", target) catch return;
}
`
	flows := taint.Analyze(code, "/app/link.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected hard link attack flow for getParamSlice -> posix.link")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — File truncation via std.posix.truncate (CWE-22)
// =========================================================================

func TestZig_FileTruncate_PosixTruncate(t *testing.T) {
	code := `
const std = @import("std");

pub fn clear_file(request: zap.Request) void {
    const path = request.getParamSlice("path");
    std.posix.truncate(path, 0) catch return;
}
`
	flows := taint.Analyze(code, "/app/truncate.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file truncate flow for getParamSlice -> posix.truncate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
