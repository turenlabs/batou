package tsflow

// zig-sqlite (vrischmann/zig-sqlite) read-result source taint tests.
// Zig flows through the regex-based taint.Analyze engine because there is
// no tree-sitter grammar registered for Zig in ast/languages.go.
//
// These tests pair with the existing zig.sqlite.exec/prepare/execDynamic
// sinks: data attacker-controlled in an earlier write may be read back via
// db.one / stmt.one / stmt.all / stmt.iterator / iter.next* and flowed to
// a dangerous sink (path traversal, command injection, XSS, etc.).

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// zig-sqlite — Db.one(...) row -> openFileAbsolute (path traversal, CWE-22)
// =========================================================================

func TestZig_SQLite_DbOne_PathTraversal(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db) !void {
    const path = try db.one([]const u8, "SELECT path FROM cache LIMIT 1", .{}, .{});
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/cache.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Db.one -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// zig-sqlite — Stmt.one(...) row -> openFileAbsolute (path traversal)
// =========================================================================

func TestZig_SQLite_StmtOne_PathTraversal(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db) !void {
    var stmt = try db.prepare("SELECT path FROM users WHERE id = ?");
    defer stmt.deinit();
    const path = try stmt.one([]const u8, .{}, .{ .id = 1 });
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/users.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Stmt.one -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// zig-sqlite — Stmt.oneAlloc(...) row -> openFileAbsolute (path traversal)
// =========================================================================

func TestZig_SQLite_StmtOneAlloc_PathTraversal(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db, allocator: std.mem.Allocator) !void {
    var stmt = try db.prepare("SELECT path FROM uploads LIMIT 1");
    defer stmt.deinit();
    const path = try stmt.oneAlloc([]const u8, allocator, .{}, .{});
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/uploads.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Stmt.oneAlloc -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// zig-sqlite — Stmt.all(...) rows -> std.fs.openFileAbsolute (path traversal)
// =========================================================================

func TestZig_SQLite_StmtAll_PathTraversal(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db, allocator: std.mem.Allocator) !void {
    var stmt = try db.prepare("SELECT path FROM cache");
    defer stmt.deinit();
    const paths = try stmt.all([]const u8, allocator, .{}, .{});
    const file = try std.fs.openFileAbsolute(paths, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/all.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Stmt.all -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// zig-sqlite — Stmt.iterator(...) -> openFileAbsolute (the iterator handle is
// itself the carrier of DB-sourced data; flowing it through openFileAbsolute
// is a contrived smoke test that confirms the source fires).
// =========================================================================

func TestZig_SQLite_StmtIterator_Source(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db) !void {
    var stmt = try db.prepare("SELECT name FROM users");
    defer stmt.deinit();
    const data = try stmt.iterator([]const u8, .{});
    const file = try std.fs.openFileAbsolute(data, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/iter.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Stmt.iterator -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// zig-sqlite — iter.next() row -> openFileAbsolute (path traversal)
// =========================================================================

func TestZig_SQLite_IteratorNext_PathTraversal(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db) !void {
    var stmt = try db.prepare("SELECT path FROM rows");
    defer stmt.deinit();
    var iter = try stmt.iterator([]const u8, .{});
    const path = try iter.next(.{});
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/iternext.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Iterator.next -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// zig-sqlite — iter.nextAlloc() row -> openFileAbsolute (path traversal)
// =========================================================================

func TestZig_SQLite_IteratorNextAlloc_PathTraversal(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db, allocator: std.mem.Allocator) !void {
    var stmt = try db.prepare("SELECT name FROM users");
    defer stmt.deinit();
    var iter = try stmt.iterator([]const u8, .{});
    const name = try iter.nextAlloc(allocator, .{});
    const file = try std.fs.openFileAbsolute(name, .{});
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/iternextalloc.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for sqlite Iterator.nextAlloc -> std.fs.openFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative test — constant SQL plumbed only between sqlite calls (no sink)
// should not produce a flow. Guards against over-broadness regressions.
// =========================================================================

func TestZig_SQLite_SourceWithoutSink_NoFlow(t *testing.T) {
	code := `
const std = @import("std");
const sqlite = @import("sqlite");

fn handler(db: *sqlite.Db) !void {
    var stmt = try db.prepare("SELECT 1");
    defer stmt.deinit();
    const _ = try stmt.one(i32, .{}, .{});
}
`
	flows := taint.Analyze(code, "/app/noflow.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected %s flow (no dangerous sink in fixture)", f.Sink.Category)
		}
	}
}
