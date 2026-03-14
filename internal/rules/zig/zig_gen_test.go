package zig

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- ZIG-009: @memcpy Buffer Overflow ---

func TestZIG009_Vulnerable(t *testing.T) {
	content := `const std = @import("std");
pub fn copyData(dest: []u8, src: []const u8) void {
    @memcpy(dest.ptr, src.ptr, src.len);
}`
	result := testutil.ScanContent(t, "/app/mem.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-009")
}

func TestZIG009_VulnerableInline(t *testing.T) {
	content := `@memcpy(buffer.ptr, input.ptr, input.len);`
	result := testutil.ScanContent(t, "/app/mem.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-009")
}

func TestZIG009_Safe(t *testing.T) {
	content := `const std = @import("std");
pub fn safeCopy(dest: []u8, src: []const u8) void {
    const len = @min(dest.len, src.len);
    std.mem.copyForwards(u8, dest[0..len], src[0..len]);
}`
	result := testutil.ScanContent(t, "/app/mem.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-009")
}

// --- ZIG-010: std.c.system/popen Command Injection ---

func TestZIG010_VulnerableSystem(t *testing.T) {
	content := `const std = @import("std");
pub fn execute(cmd: [*:0]const u8) void {
    _ = std.c.system(cmd);
}`
	result := testutil.ScanContent(t, "/app/exec.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-010")
}

func TestZIG010_VulnerablePopen(t *testing.T) {
	content := `const std = @import("std");
pub fn run(cmd: [*:0]const u8) void {
    const pipe = std.c.popen(cmd, "r");
    _ = pipe;
}`
	result := testutil.ScanContent(t, "/app/exec.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-010")
}

func TestZIG010_Safe(t *testing.T) {
	content := `const std = @import("std");
pub fn run() !void {
    var child = std.process.Child.init(.{
        .argv = &[_][]const u8{"ls", "-la"},
    }, std.heap.page_allocator);
    _ = try child.spawnAndWait();
}`
	result := testutil.ScanContent(t, "/app/exec.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-010")
}

// --- ZIG-011: @intCast Overflow with External Data ---

func TestZIG011_Vulnerable(t *testing.T) {
	content := `const std = @import("std");
pub fn handleRequest(data: []const u8) void {
    const len: u16 = @intCast(u16, parseInput(data));
    _ = len;
}
fn parseInput(d: []const u8) usize { return d.len; }`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-011")
}

func TestZIG011_VulnerableReadLine(t *testing.T) {
	content := `const std = @import("std");
pub fn process() !void {
    const input = try std.io.getStdIn().reader().readUntilDelimiterAlloc(std.heap.page_allocator, '\n', 4096);
    const size: u8 = @intCast(u8, input.len);
    _ = size;
}`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-011")
}

func TestZIG011_Safe_NoExternalContext(t *testing.T) {
	content := `const std = @import("std");
pub fn convert() void {
    const x: u32 = 42;
    const y: u16 = @intCast(u16, x);
    _ = y;
}`
	result := testutil.ScanContent(t, "/app/math.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-011")
}

// --- ZIG-012: Allocator Use-After-Free ---

func TestZIG012_VulnerableFree(t *testing.T) {
	content := `const std = @import("std");
pub fn process(allocator: std.mem.Allocator) !void {
    const buf = try allocator.alloc(u8, 1024);
    allocator.free(buf);
}`
	result := testutil.ScanContent(t, "/app/alloc.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-012")
}

func TestZIG012_VulnerableDeinit(t *testing.T) {
	content := `const std = @import("std");
pub fn cleanup(list: *std.ArrayList(u8)) void {
    list.deinit();
}`
	result := testutil.ScanContent(t, "/app/alloc.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-012")
}

func TestZIG012_Safe(t *testing.T) {
	content := `const std = @import("std");
pub fn process(allocator: std.mem.Allocator) !void {
    const buf = try allocator.alloc(u8, 1024);
    defer allocator.destroy(buf);
    doWork(buf);
}`
	result := testutil.ScanContent(t, "/app/alloc.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-012")
}

// --- ZIG-013: Missing errdefer ---

func TestZIG013_Vulnerable(t *testing.T) {
	content := `const std = @import("std");
pub fn init(allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    self.data = try allocator.alloc(u8, 1024);
    return self;
}`
	result := testutil.ScanContent(t, "/app/resource.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-013")
}

func TestZIG013_Safe_WithErrdefer(t *testing.T) {
	content := `const std = @import("std");
pub fn init(allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    errdefer allocator.destroy(self);
    self.data = try allocator.alloc(u8, 1024);
    errdefer allocator.free(self.data);
    return self;
}`
	result := testutil.ScanContent(t, "/app/resource.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-013")
}

// --- ZIG-014: @embedFile Sensitive Data ---

func TestZIG014_VulnerableKey(t *testing.T) {
	content := `const std = @import("std");
const private_key = @embedFile("certs/private_key.pem");`
	result := testutil.ScanContent(t, "/app/crypto.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-014")
}

func TestZIG014_VulnerableSecret(t *testing.T) {
	content := `const api_secret = @embedFile("config/secret.json");`
	result := testutil.ScanContent(t, "/app/config.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-014")
}

func TestZIG014_VulnerableToken(t *testing.T) {
	content := `const auth_token = @embedFile("auth/token.dat");`
	result := testutil.ScanContent(t, "/app/auth.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-014")
}

func TestZIG014_Safe(t *testing.T) {
	content := `const std = @import("std");
const template = @embedFile("templates/index.html");
const shader = @embedFile("shaders/vertex.glsl");`
	result := testutil.ScanContent(t, "/app/assets.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-014")
}

// --- ZIG-015: std.net.Stream Without TLS ---

func TestZIG015_Vulnerable(t *testing.T) {
	content := `const std = @import("std");
pub fn connect(addr: std.net.Address) !std.net.Stream {
    return std.net.tcpConnectToAddress(addr);
}`
	result := testutil.ScanContent(t, "/app/net.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-015")
}

func TestZIG015_Safe_WithTLS(t *testing.T) {
	content := `const std = @import("std");
const tls = std.crypto.tls;
pub fn connect(addr: std.net.Address) !std.net.Stream {
    const stream = try std.net.tcpConnectToAddress(addr);
    const tls_stream = try tls.client(stream);
    return tls_stream;
}`
	result := testutil.ScanContent(t, "/app/net.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-015")
}

func TestZIG015_Safe_WithSSL(t *testing.T) {
	content := `const std = @import("std");
// Using ssl wrapper around std.net.Stream
const ssl_ctx = initSSL();
pub fn connect(addr: std.net.Address) !std.net.Stream {
    return std.net.tcpConnectToAddress(addr);
}`
	result := testutil.ScanContent(t, "/app/net.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-015")
}

// --- ZIG-016: Sentinel Slice Bypass ---

func TestZIG016_Vulnerable(t *testing.T) {
	content := `const std = @import("std");
pub fn toRaw(s: [:0]const u8) [*]const u8 {
    return @ptrCast([*]const u8, s.ptr);
}`
	result := testutil.ScanContent(t, "/app/interop.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-016")
}

func TestZIG016_VulnerableMultiByte(t *testing.T) {
	content := `const raw = @ptrCast([*]u16, wide_str.ptr);`
	result := testutil.ScanContent(t, "/app/interop.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-016")
}

func TestZIG016_Safe(t *testing.T) {
	content := `const std = @import("std");
pub fn toCStr(s: [:0]const u8) [*:0]const u8 {
    return s.ptr;
}`
	result := testutil.ScanContent(t, "/app/interop.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-016")
}

// --- ZIG-017: C String Interop Without Null Termination ---

func TestZIG017_Vulnerable(t *testing.T) {
	content := `const c = @cImport(@cInclude("string.h"));
pub fn getLength(s: []const u8) usize {
    const c_str = @ptrCast([*]const u8, s.ptr, s.len);
    return c.strlen(c_str);
}`
	result := testutil.ScanContent(t, "/app/ffi.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-017")
}

func TestZIG017_VulnerableStdC(t *testing.T) {
	content := `const std = @import("std");
pub fn printStr(s: []const u8) void {
    const c_ptr = @ptrCast([*]const u8, s.ptr, s.len);
    _ = std.c.puts(c_ptr);
}`
	result := testutil.ScanContent(t, "/app/ffi.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-017")
}

func TestZIG017_Safe_NoCInterop(t *testing.T) {
	content := `const std = @import("std");
pub fn process(s: []const u8) void {
    const raw = @ptrCast([*]const u8, s.ptr, s.len);
    _ = raw;
}`
	result := testutil.ScanContent(t, "/app/pure.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-017")
}

func TestZIG017_Safe_SentinelBypass(t *testing.T) {
	// When the line matches ZIG-016 pattern (@ptrCast(*.ptr)), ZIG-017 excludes it
	content := `const c = @cImport(@cInclude("string.h"));
pub fn wrap(s: [:0]const u8) [*]const u8 {
    return @ptrCast([*]const u8, s.ptr);
}`
	result := testutil.ScanContent(t, "/app/ffi.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-017")
}

// --- ZIG-018: Format String with Runtime Data ---

func TestZIG018_VulnerableFmt(t *testing.T) {
	content := `const std = @import("std");
pub fn handle(user_input: []const u8) !void {
    var buf: [1024]u8 = undefined;
    _ = try std.fmt.format(buf[0..], "received from user: {s}", .{user_input});
}`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-018")
}

func TestZIG018_VulnerableLog(t *testing.T) {
	content := `const std = @import("std");
pub fn logAction(user_name: []const u8) void {
    std.log.info("action by user: {s}", .{user_name});
}`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-018")
}

func TestZIG018_VulnerableLogWarn(t *testing.T) {
	content := `const std = @import("std");
pub fn warnUser(user_id: u64) void {
    std.log.warn("suspicious user id={d}", .{user_id});
}`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustFindRule(t, result, "BATOU-ZIG-018")
}

func TestZIG018_Safe_NoUserData(t *testing.T) {
	content := `const std = @import("std");
pub fn logStartup() void {
    std.log.info("server started on port {d}", .{8080});
}`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-018")
}

func TestZIG018_Safe_FmtNoUser(t *testing.T) {
	content := `const std = @import("std");
pub fn format(val: u32) !void {
    var buf: [64]u8 = undefined;
    _ = try std.fmt.format(buf[0..], "value={d}", .{val});
}`
	result := testutil.ScanContent(t, "/app/handler.zig", content)
	testutil.MustNotFindRule(t, result, "BATOU-ZIG-018")
}
