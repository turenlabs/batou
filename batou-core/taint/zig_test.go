package taint_test

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasFlow(flows []taint.TaintFlow, sink taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == sink {
			return true
		}
	}
	return false
}

func TestZig_Zap_XSS(t *testing.T) {
	code := `const std = @import("std");
const zap = @import("zap");

fn handle(r: zap.Request) void {
    const name = r.getParamSlice("name");
    r.sendBody(name) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for zap getParamSlice -> sendBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Httpz_SQLInjection(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const id = req.param("id");
    const query = std.fmt.allocPrint(allocator, "SELECT * FROM users WHERE id = " ++ id);
    db.exec(query) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz param -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Httpz_PathTraversal(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const path = req.body();
    const dir = std.fs.cwd() catch return;
    const file = dir.openFile(path, .{}) catch return;
    defer file.close();
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileRead) {
		t.Error("expected path traversal flow for httpz body -> openFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_StdLib_CommandInjection(t *testing.T) {
	code := `const std = @import("std");

fn run(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    std.os.execve(args[0], args, &[_][]const u8{});
}
`
	flows := taint.Analyze(code, "/app/runner.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for argsAlloc -> execve")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_HTMLEscape_Sanitized(t *testing.T) {
	code := `const std = @import("std");
const zap = @import("zap");

fn handle(r: zap.Request) void {
    const name = r.getParamSlice("name");
    std.html.escape(writer, name);
    r.sendBody(escaped) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when std.html.escape is used as sanitizer")
		}
	}
}

func TestZig_WeakPRNG_CatalogEntry(t *testing.T) {
	// Weak PRNG sinks are usage-based (DangerousArgs: -1), not source->sink flows.
	// Verify the catalog entry exists and the pattern matches.
	cat := taint.GetCatalog(rules.LangZig)
	if cat == nil {
		t.Fatal("no catalog for Zig")
	}
	sinks := cat.Sinks()
	found := false
	for _, s := range sinks {
		if s.ID == "zig.rand.DefaultPrng.init" {
			found = true
			if s.Category != taint.SnkCrypto {
				t.Errorf("expected SnkCrypto category, got %s", s.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected sink entry for zig.rand.DefaultPrng.init")
	}
}

func TestZig_PgZig_SQLInjection(t *testing.T) {
	code := `const std = @import("std");
const pg = @import("pg");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const id = req.param("id");
    const sql = std.fmt.allocPrint(allocator, "SELECT * FROM users WHERE id = {s}", .{id});
    var result = conn.query(sql, .{}) catch return;
    defer result.deinit();
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz param -> conn.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_PgZig_Exec(t *testing.T) {
	code := `const std = @import("std");
const pg = @import("pg");

fn deleteUser(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    const sql = std.fmt.allocPrint(allocator, "DELETE FROM users WHERE name = '{s}'", .{args[1]});
    _ = conn.exec(sql, .{}) catch return;
}
`
	flows := taint.Analyze(code, "/app/admin.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argsAlloc -> conn.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_PgZig_Row(t *testing.T) {
	code := `const std = @import("std");
const pg = @import("pg");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const email = req.param("email");
    const sql = std.fmt.allocPrint(allocator, "SELECT * FROM users WHERE email = '{s}'", .{email});
    const user = conn.row(sql, .{}) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz param -> conn.row")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Jetzig_RenderText_XSS(t *testing.T) {
	code := `const std = @import("std");
const jetzig = @import("jetzig");

pub fn index(request: *jetzig.Request) !jetzig.View {
    const name = request.params().get("name");
    return request.renderText(name, .ok);
}
`
	flows := taint.Analyze(code, "/app/views/users.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for jetzig params -> renderText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Jetzig_Redirect(t *testing.T) {
	code := `const std = @import("std");
const jetzig = @import("jetzig");

pub fn index(request: *jetzig.Request) !jetzig.View {
    const url = request.queryParams().get("next");
    return request.redirect(url, .found);
}
`
	flows := taint.Analyze(code, "/app/views/auth.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for jetzig queryParams -> redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_LogDebug_Injection(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const user = req.header("X-User");
    std.log.debug("user login: {s}", .{user});
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for httpz header -> std.log.debug")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ChildRun_CommandInjection(t *testing.T) {
	code := `const std = @import("std");

fn run(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    const result = std.process.Child.run(args) catch return;
}
`
	flows := taint.Analyze(code, "/app/runner.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for argsAlloc -> Child.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_PgZig_PoolQuery(t *testing.T) {
	code := `const std = @import("std");
const pg = @import("pg");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const search = req.param("q");
    const sql = std.fmt.allocPrint(allocator, "SELECT * FROM products WHERE name LIKE '%{s}%'", .{search});
    var result = pool.query(sql, .{}) catch return;
    defer result.deinit();
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for httpz param -> pool.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Zap_Cookie_Source(t *testing.T) {
	code := `const std = @import("std");
const zap = @import("zap");

fn handle(r: zap.Request) void {
    const session = r.getCookieStr(allocator, "session", false);
    std.os.execve(session, &[_][]const u8{}, &[_][]const u8{});
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getCookieStr -> execve")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_System_CommandInjection(t *testing.T) {
	code := `const std = @import("std");

fn handler(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    const cmd = args[1];
    _ = std.c.system(cmd);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for argsAlloc -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_Fopen_PathTraversal(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const path = req.param("file");
    const fp = std.c.fopen(path, "r");
    defer if (fp) |f| std.c.fclose(f);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for httpz param -> std.c.fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_DynLib_Open_CodeExecution(t *testing.T) {
	code := `const std = @import("std");

fn loadPlugin(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    const lib_path = args[1];
    var lib = std.DynLib.open(lib_path) catch return;
    defer lib.close();
}
`
	flows := taint.Analyze(code, "/app/plugin.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkEval) {
		t.Error("expected code execution flow for argsAlloc -> DynLib.open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_DebugPrint_InfoDisclosure(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const token = req.header("Authorization");
    std.debug.print("auth: {s}\n", .{token});
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for httpz header -> std.debug.print")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_Popen_CommandInjection(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const cmd = req.param("cmd");
    const pipe = std.c.popen(cmd, "r");
    defer if (pipe) |p| _ = std.c.pclose(p);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for httpz param -> std.c.popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_MemReplace_Sanitized(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const input = req.header("X-Log-Tag");
    var buf: [256]u8 = undefined;
    const clean = std.mem.replace(u8, input, "\n", "_", &buf);
    std.log.info("{s}", .{clean});
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when std.mem.replace sanitizes input")
		}
	}
}

func TestZig_CInterop_Printf_FormatString(t *testing.T) {
	code := `const std = @import("std");

fn run(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    const fmt = args[1];
    _ = std.c.printf(fmt);
}
`
	flows := taint.Analyze(code, "/app/runner.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkEval) {
		t.Error("expected format string flow for argsAlloc -> std.c.printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_Chmod_PermissionManipulation(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const path = req.param("path");
    _ = std.c.chmod(path, 0o777);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for httpz param -> std.c.chmod")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_Unlink_PathDeletion(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const path = req.param("file");
    _ = std.c.unlink(path);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for httpz param -> std.c.unlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Posix_Unlink_PathDeletion(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const path = req.param("file");
    std.posix.unlink(path) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for httpz param -> std.posix.unlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_Dlopen_CodeExecution(t *testing.T) {
	code := `const std = @import("std");

fn loadPlugin(allocator: std.mem.Allocator) void {
    const args = std.process.argsAlloc(allocator) catch return;
    const lib_path = args[1];
    const handle = std.c.dlopen(lib_path, 1);
    defer if (handle) |h| _ = std.c.dlclose(h);
}
`
	flows := taint.Analyze(code, "/app/plugin.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkCommand) {
		t.Error("expected command exec flow for argsAlloc -> std.c.dlopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_CInterop_Getenv_Source(t *testing.T) {
	code := `const std = @import("std");

fn run() void {
    const path = std.c.getenv("USER_PATH");
    _ = std.c.chmod(path, 0o777);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for std.c.getenv -> std.c.chmod")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Posix_Rmdir_PathDeletion(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const dir = req.param("dir");
    std.posix.rmdir(dir) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for httpz param -> std.posix.rmdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Posix_Chdir_PathManipulation(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const dir = req.param("dir");
    std.posix.chdir(dir) catch return;
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	if !hasFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for httpz param -> std.posix.chdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_Posix_Realpath_Sanitized(t *testing.T) {
	code := `const std = @import("std");
const httpz = @import("httpz");

fn handle(req: *httpz.Request, res: *httpz.Response) void {
    const path = req.param("file");
    const resolved = std.posix.realpath(path, &buf) catch return;
    _ = std.c.unlink(resolved);
}
`
	flows := taint.Analyze(code, "/app/handler.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Error("expected NO file write flow when std.posix.realpath sanitizes input")
		}
	}
}
