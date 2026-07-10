package tsflow

// Zig httpz (karlseguin/http.zig) response-sink taint tests.
// Zig flows through the regex-based taint.Analyze engine because there is
// no tree-sitter grammar registered for Zig in ast/languages.go.

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Zig — XSS via httpz res.json (CWE-79)
// =========================================================================

func TestZig_XSS_HttpzResJson(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, res: *httpz.Response) !void {
    const user_input = try req.param("name");
    try res.json(.{ .echo = user_input }, .{});
}
`
	flows := taint.Analyze(code, "/app/httpz_api.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for httpz req.param -> res.json")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Header injection via httpz res.header (CWE-113)
// =========================================================================

func TestZig_HeaderInjection_HttpzResHeader(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, res: *httpz.Response) !void {
    const tainted = try req.header("X-User");
    res.header("X-Echo", tainted);
}
`
	flows := taint.Analyze(code, "/app/httpz_hdr.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for httpz req.header -> res.header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Cookie injection via httpz res.setCookie (CWE-113)
// =========================================================================

func TestZig_HeaderInjection_HttpzSetCookie(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, res: *httpz.Response) !void {
    const user_val = try req.query("session");
    try res.setCookie("sid", user_val, .{ .path = "/" });
}
`
	flows := taint.Analyze(code, "/app/httpz_cookie.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for httpz req.query -> res.setCookie")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Open redirect via httpz res.header("Location", ...) (CWE-601)
// =========================================================================

func TestZig_OpenRedirect_HttpzLocationHeader(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, res: *httpz.Response) !void {
    const next = try req.query("next");
    res.header("Location", next);
    res.status = 302;
}
`
	flows := taint.Analyze(code, "/app/httpz_redir.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for httpz req.query -> res.header(Location,...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Header injection via httpz res.headerOpts (CWE-113)
// =========================================================================

func TestZig_HeaderInjection_HttpzHeaderOpts(t *testing.T) {
	code := `
const std = @import("std");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, res: *httpz.Response) !void {
    const tainted = try req.header("X-Forward");
    try res.headerOpts("X-Echo", tainted, .{ .dupe_value = true });
}
`
	flows := taint.Analyze(code, "/app/httpz_hdropts.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for httpz req.header -> res.headerOpts")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
