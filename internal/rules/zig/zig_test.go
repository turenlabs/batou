package zig

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- ZIG-001: Unsafe @ptrCast ---

func TestZIG001_PtrCast(t *testing.T) {
	content := `const std = @import("std");
pub fn convert(ptr: *const u8) *const u32 {
    return @ptrCast(*const u32, ptr);
}`
	result := testutil.ScanContent(t, "/app/cast.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-001")
}

func TestZIG001_PtrCastInline(t *testing.T) {
	content := `const val = @ptrCast([*]u8, slice.ptr);`
	result := testutil.ScanContent(t, "/app/cast.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-001")
}

func TestZIG001_Safe_NoPtrCast(t *testing.T) {
	content := `const std = @import("std");
pub fn safe() void {
    const x: u32 = @as(u32, 42);
    _ = x;
}`
	result := testutil.ScanContent(t, "/app/safe.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-001")
}

// --- ZIG-002: Unsafe @intToPtr ---

func TestZIG002_IntToPtr(t *testing.T) {
	content := `const ptr = @intToPtr(*u32, 0xDEADBEEF);`
	result := testutil.ScanContent(t, "/app/ptr.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-002")
}

func TestZIG002_IntToPtrWithVar(t *testing.T) {
	content := `const addr: usize = get_address();
const ptr = @intToPtr(*volatile u8, addr);`
	result := testutil.ScanContent(t, "/app/mmio.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-002")
}

func TestZIG002_Safe_NoIntToPtr(t *testing.T) {
	content := `const std = @import("std");
pub fn safe() void {
    var x: usize = 42;
    x += 1;
}`
	result := testutil.ScanContent(t, "/app/safe.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-002")
}

// --- ZIG-003: Unsafe @alignCast ---

func TestZIG003_AlignCast(t *testing.T) {
	content := `const aligned = @alignCast(@alignOf(u32), raw_ptr);`
	result := testutil.ScanContent(t, "/app/align.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-003")
}

func TestZIG003_Safe_NoAlignCast(t *testing.T) {
	content := `const std = @import("std");
const x: u32 = 42;
const y = @as(u64, x);`
	result := testutil.ScanContent(t, "/app/safe.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-003")
}

// --- ZIG-004: Command Injection ---

func TestZIG004_ChildProcess(t *testing.T) {
	content := `const std = @import("std");
pub fn run(cmd: []const u8) !void {
    var child = std.process.Child.init(.{
        .argv = &[_][]const u8{cmd},
    }, std.heap.page_allocator);
}`
	result := testutil.ScanContent(t, "/app/exec.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-004")
}

func TestZIG004_OsExecve(t *testing.T) {
	content := `const std = @import("std");
pub fn exec(path: []const u8) !void {
    return std.os.execve(path, &[_][]const u8{}, &[_][]const u8{});
}`
	result := testutil.ScanContent(t, "/app/exec.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-004")
}

func TestZIG004_Safe_NoExec(t *testing.T) {
	content := `const std = @import("std");
pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Hello\n", .{});
}`
	result := testutil.ScanContent(t, "/app/safe.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-004")
}

// --- ZIG-005: Path Traversal ---

func TestZIG005_FsOpenWithConcat(t *testing.T) {
	content := `const std = @import("std");
pub fn readFile(user_path: []const u8) !void {
    const path = "/data/" ++ "/" ++ user_path;
    const file = std.fs.openFile(path, .{});
    _ = file;
}`
	result := testutil.ScanContent(t, "/app/files.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-005")
}

func TestZIG005_FsOpenWithFmt(t *testing.T) {
	content := `const std = @import("std");
pub fn readFile(allocator: std.mem.Allocator, name: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "/uploads/{s}", .{name});
    const file = std.fs.openFile(path, .{});
    _ = file;
}`
	result := testutil.ScanContent(t, "/app/files.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-005")
}

func TestZIG005_Safe_WithRealpath(t *testing.T) {
	content := `const std = @import("std");
pub fn readFile(user_path: []const u8) !void {
    const resolved = try std.fs.realpathZ(user_path);
    const file = try std.fs.openFile(resolved, .{});
    _ = file;
}`
	result := testutil.ScanContent(t, "/app/files.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-005")
}

// --- ZIG-006: Unsafe Error Suppression ---

func TestZIG006_CatchUnreachable(t *testing.T) {
	content := `const value = parse(input) catch unreachable;`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-006")
}

func TestZIG006_CatchUndefined(t *testing.T) {
	content := `const result = operation() catch |_| undefined;`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-006")
}

func TestZIG006_Safe_CatchReturn(t *testing.T) {
	content := `const value = parse(input) catch |err| {
    std.log.err("parse failed: {}", .{err});
    return error.ParseFailed;
};`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-006")
}

func TestZIG006_Safe_Try(t *testing.T) {
	content := `const value = try parse(input);`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-006")
}

// --- ZIG-007: Unsafe @bitCast ---

func TestZIG007_BitCast(t *testing.T) {
	content := `const f: f32 = 3.14;
const bits = @bitCast(u32, f);`
	result := testutil.ScanContent(t, "/app/cast.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-007")
}

func TestZIG007_BitCastPointer(t *testing.T) {
	content := `const raw = @bitCast([*]u8, ptr);`
	result := testutil.ScanContent(t, "/app/cast.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-007")
}

func TestZIG007_Safe_NoBitCast(t *testing.T) {
	content := `const x: u32 = 42;
const y: u64 = @as(u64, x);`
	result := testutil.ScanContent(t, "/app/safe.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-007")
}

// --- ZIG-008: Weak Crypto ---

func TestZIG008_Md5(t *testing.T) {
	content := `const std = @import("std");
const Md5 = std.crypto.hash.Md5;
pub fn hashData(data: []const u8) [16]u8 {
    var h = Md5.init(.{});
    h.update(data);
    return h.finalResult();
}`
	result := testutil.ScanContent(t, "/app/crypto.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-008")
}

func TestZIG008_Sha1(t *testing.T) {
	content := `const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;`
	result := testutil.ScanContent(t, "/app/crypto.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-008")
}

func TestZIG008_Safe_Sha256(t *testing.T) {
	content := `const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
pub fn hashData(data: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(data);
    return h.finalResult();
}`
	result := testutil.ScanContent(t, "/app/crypto.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-008")
}

// --- Fixture Tests ---

func TestFixture_VulnerableCommandInjection(t *testing.T) {
	if !testutil.FixtureExists("zig/vulnerable/command_injection.zig") {
		t.Skip("Zig vulnerable command injection fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/vulnerable/command_injection.zig")
	result := testutil.ScanContent(t, "/app/exec.zig", content)
	testutil.AssertMinFindings(t, result, 1)
}

func TestFixture_VulnerableUnsafePointers(t *testing.T) {
	if !testutil.FixtureExists("zig/vulnerable/unsafe_pointers.zig") {
		t.Skip("Zig vulnerable unsafe pointers fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/vulnerable/unsafe_pointers.zig")
	result := testutil.ScanContent(t, "/app/unsafe.zig", content)
	testutil.AssertMinFindings(t, result, 1)
}

func TestFixture_VulnerablePathTraversal(t *testing.T) {
	if !testutil.FixtureExists("zig/vulnerable/path_traversal.zig") {
		t.Skip("Zig vulnerable path traversal fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/vulnerable/path_traversal.zig")
	result := testutil.ScanContent(t, "/app/files.zig", content)
	testutil.AssertMinFindings(t, result, 1)
}

func TestFixture_VulnerableErrorSuppression(t *testing.T) {
	if !testutil.FixtureExists("zig/vulnerable/error_suppression.zig") {
		t.Skip("Zig vulnerable error suppression fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/vulnerable/error_suppression.zig")
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.AssertMinFindings(t, result, 1)
}

func TestFixture_SafePointers(t *testing.T) {
	if !testutil.FixtureExists("zig/safe/safe_pointers.zig") {
		t.Skip("Zig safe pointers fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/safe/safe_pointers.zig")
	result := testutil.ScanContent(t, "/app/safe.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-001")
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-002")
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-003")
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-007")
}

func TestFixture_SafeFileOps(t *testing.T) {
	if !testutil.FixtureExists("zig/safe/safe_file_ops.zig") {
		t.Skip("Zig safe file ops fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/safe/safe_file_ops.zig")
	result := testutil.ScanContent(t, "/app/files.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-005")
}

func TestFixture_SafeErrorHandling(t *testing.T) {
	if !testutil.FixtureExists("zig/safe/safe_error_handling.zig") {
		t.Skip("Zig safe error handling fixture not available")
	}
	content := testutil.LoadFixture(t, "zig/safe/safe_error_handling.zig")
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-006")
}
