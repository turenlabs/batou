package tsflow

// Zig does not have a tree-sitter grammar registered in ast/languages.go,
// so tsflow.Analyze falls through to the regex-based taint.Analyze engine.
// These tests cover the runtime-SQL variants exposed by vrischmann/zig-sqlite:
//   - Db.execMulti              (multi-statement runtime SQL)
//   - Db.oneDynamic             (single-row runtime SQL)
//   - Db.oneDynamicAlloc        (single-row runtime SQL with allocator)
//   - Db.prepareDynamic         (DynamicStatement from runtime SQL)
//   - Db.prepareDynamicWithDiags(DynamicStatement with diagnostics)
//
// Each method takes a non-comptime SQL string, so a tainted query parameter
// is a real CWE-89 injection sink even when the values are bound separately.

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func TestZig_SQLi_SQLite_ExecMulti(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, db: *sqlite.Db) !void {
    const user_input = try req.body();
    var buf: [512]u8 = undefined;
    const sql = try std.fmt.bufPrint(&buf, "INSERT INTO logs VALUES('{s}'); DELETE FROM logs WHERE id < 0;", .{user_input});
    try db.execMulti(sql, .{});
}
`
	flows := taint.Analyze(code, "/app/log_handler.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz body -> Db.execMulti")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_SQLi_SQLite_OneDynamic(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");

const User = struct { id: u64, name: []const u8 };

fn lookup(req: *httpz.Request, db: *sqlite.Db) !void {
    const user_input = try req.body();
    var buf: [256]u8 = undefined;
    const sql = try std.fmt.bufPrint(&buf, "SELECT id, name FROM users WHERE name = '{s}'", .{user_input});
    _ = try db.oneDynamic(User, sql, .{}, .{});
}
`
	flows := taint.Analyze(code, "/app/lookup.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz body -> Db.oneDynamic")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_SQLi_SQLite_OneDynamicAlloc(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");
const zap = @import("zap");

const Row = struct { id: u64, payload: []const u8 };

fn handler(request: zap.Request, db: *sqlite.Db, allocator: std.mem.Allocator) !void {
    const user_input = request.getParamSlice("q") orelse return;
    var buf: [256]u8 = undefined;
    const sql = try std.fmt.bufPrint(&buf, "SELECT id, payload FROM rows WHERE payload LIKE '%{s}%'", .{user_input});
    _ = try db.oneDynamicAlloc(Row, allocator, sql, .{}, .{});
}
`
	flows := taint.Analyze(code, "/app/zap_search.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for zap getParamSlice -> Db.oneDynamicAlloc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_SQLi_SQLite_PrepareDynamic(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, db: *sqlite.Db) !void {
    const user_input = try req.body();
    var buf: [256]u8 = undefined;
    const sql = try std.fmt.bufPrint(&buf, "DELETE FROM accounts WHERE owner = '{s}'", .{user_input});
    var stmt = try db.prepareDynamic(sql);
    defer stmt.deinit();
}
`
	flows := taint.Analyze(code, "/app/delete_acct.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz body -> Db.prepareDynamic")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_SQLi_SQLite_PrepareDynamicWithDiags(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, db: *sqlite.Db) !void {
    const user_input = try req.body();
    var buf: [256]u8 = undefined;
    const sql = try std.fmt.bufPrint(&buf, "UPDATE accounts SET note = '{s}' WHERE id = 1", .{user_input});
    var diags: sqlite.Diagnostics = .{};
    var stmt = try db.prepareDynamicWithDiags(sql, .{ .diags = &diags });
    defer stmt.deinit();
}
`
	flows := taint.Analyze(code, "/app/diag_update.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz body -> Db.prepareDynamicWithDiags")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test — using the comptime-checked Db.prepare path with bind() should
// be neutralized by the existing zig.sqlite.prepareWithBind sanitizer. This
// verifies the new dynamic-SQL sinks don't widen taint to safe parameterised
// usage of the library.
func TestZig_SQLi_SQLite_SafePrepareWithBind_NoFlow(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");

fn handler(req: *httpz.Request, db: *sqlite.Db) !void {
    const user_input = try req.body();
    var stmt = try db.prepare("UPDATE accounts SET note = ? WHERE id = 1");
    defer stmt.deinit();
    try stmt.bind(.{user_input});
}
`
	flows := taint.Analyze(code, "/app/safe_bind.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence >= 0.7 {
			t.Errorf("unexpected high-confidence SQL flow on parameterised stmt.bind path: sink=%s conf=%.2f", f.Sink.ID, f.Confidence)
		}
	}
}
