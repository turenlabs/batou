package zigast

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

func scanZig(t *testing.T, code string) []rules.Finding {
	t.Helper()
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.zig",
		Content:  code,
		Language: rules.LangZig,
	}
	a := &ZigASTAnalyzer{}
	return a.Scan(ctx)
}

func hasRule(findings []rules.Finding, id string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == id {
			return &findings[i]
		}
	}
	return nil
}

// --- External-origin gating: positive (recall) cases ---------------------
//
// Each of these feeds an EXTERNAL source (a byte-slice parameter of a
// handler/parser-shaped fn, or a value read from posix/argv/stdin) into the
// dangerous shape, so the gate must still emit.

func TestPtrCastProvenanceExternal(t *testing.T) {
	// @ptrCast of an external handler byte-slice parameter → fires.
	code := `
pub fn parse(buf: []u8) *Header {
    const hdr: *Header = @ptrCast(buf.ptr);
    return hdr;
}
`
	f := hasRule(scanZig(t, code), "BATOU-ZIG-AST-001")
	if f == nil {
		t.Fatal("expected @ptrCast provenance finding on external byte-slice param")
	}
	if f.CWEID != "CWE-843" {
		t.Errorf("expected CWE-843, got %s", f.CWEID)
	}
}

func TestPtrCastFromExternalReadFires(t *testing.T) {
	// @ptrCast of a value read from posix.read (an explicit external source).
	code := `
pub fn run(fd: i32) *Header {
    var buf: [256]u8 = undefined;
    const data = std.posix.read(fd, buf[0..]) catch unreachable;
    const hdr: *Header = @ptrCast(data.ptr);
    return hdr;
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-001") == nil {
		t.Error("expected @ptrCast finding when operand reads from posix.read")
	}
}

func TestBitCastPointerExternal(t *testing.T) {
	// @bitCast that transmutes an EXTERNAL slice pointer → fires (pointer-bearing).
	code := `
pub fn parsePayload(payload: []const u8) *const u64 {
    const p: *const u64 = @bitCast(payload.ptr);
    return p;
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-002") == nil {
		t.Error("expected @bitCast finding on external pointer-bearing operand")
	}
}

func TestMemcpyExternalLengthIntoFixedArray(t *testing.T) {
	// @memcpy with an EXTERNAL runtime length into a fixed-size array → fires.
	code := `
pub fn handleRequest(body: []const u8) [32]u8 {
    var dest: [32]u8 = undefined;
    @memcpy(dest[0..body.len], body);
    return dest;
}
`
	f := hasRule(scanZig(t, code), "BATOU-ZIG-AST-004")
	if f == nil {
		t.Fatal("expected @memcpy finding for external length into fixed array")
	}
	if f.CWEID != "CWE-120" {
		t.Errorf("expected CWE-120, got %s", f.CWEID)
	}
}

func TestUseAfterFreeExternal(t *testing.T) {
	// UAF where the freed allocation traces to an external read → fires.
	code := `
pub fn handle(allocator: std.mem.Allocator, fd: i32) !void {
    const data = try allocator.alloc(u8, 64);
    _ = try std.posix.read(fd, data);
    allocator.free(data);
    data[0] = 1;
}
`
	f := hasRule(scanZig(t, code), "BATOU-ZIG-AST-005")
	if f == nil {
		t.Fatal("expected use-after-free finding on externally-derived allocation")
	}
	if f.CWEID != "CWE-416" {
		t.Errorf("expected CWE-416, got %s", f.CWEID)
	}
}

// --- External-origin gating: negative (precision) cases ------------------
//
// These are the safe, local/internal/comptime uses that flooded the real repo.
// The gate must NOT emit on any of them.

func TestPtrFromIntLiteralNotFlagged(t *testing.T) {
	// MMIO / constant-address pointer forge — internal, not external → no fire.
	code := `
pub fn gpio() *volatile u32 {
    return @ptrFromInt(0x4002_0000);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-003") != nil {
		t.Error("did not expect @ptrFromInt finding for a constant address")
	}
}

func TestBitCastScalarNotFlagged(t *testing.T) {
	// @bitCast of a scalar (no pointer/slice) is benign even on a param → no fire.
	code := `
pub fn t(x: u64) f64 {
    return @bitCast(x);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-002") != nil {
		t.Error("did not expect @bitCast finding for a scalar reinterpret")
	}
}

func TestPtrCastLocalNotFlagged(t *testing.T) {
	// @ptrCast of a local stack array — internal provenance → no fire.
	code := `
pub fn t() *const u32 {
    const bytes = [_]u8{ 1, 2, 3, 4 };
    return @ptrCast(&bytes);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-001") != nil {
		t.Error("did not expect @ptrCast finding for a local stack array")
	}
}

func TestMemcpyRuntimeLengthLocalNotFlagged(t *testing.T) {
	// Runtime length but local/internal operands and a slice/ptr dest → no fire.
	code := `
pub fn copy(dst: [*]u8, src: [*]const u8, len: usize) void {
    @memcpy(dst[0..len], src[0..len]);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-004") != nil {
		t.Error("did not expect @memcpy finding for non-external length into a slice dest")
	}
}

func TestMemcpyMinClampedNotFlagged(t *testing.T) {
	// External length but @min-clamped to the destination → bounded → no fire.
	code := `
pub fn fill(body: []const u8) [32]u8 {
    var dest: [32]u8 = undefined;
    const len = @min(dest.len, body.len);
    @memcpy(dest[0..len], body[0..len]);
    return dest;
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-004") != nil {
		t.Error("did not expect @memcpy finding when length is @min-clamped")
	}
}

func TestMemcpyComptimeLengthSafe(t *testing.T) {
	// A comptime literal-bounded copy is NOT flagged (no runtime length).
	code := `
pub fn copy(dst: []u8, src: []const u8) void {
    @memcpy(dst[0..16], src[0..16]);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-004") != nil {
		t.Error("did not expect a finding for comptime-literal-bounded @memcpy")
	}
}

func TestUseAfterFreeInternalNotFlagged(t *testing.T) {
	// UAF of a purely-internal allocation is NOT a request-taint hazard → no fire.
	code := `
pub fn uaf(alloc: std.mem.Allocator) void {
    const data = alloc.alloc(u8, 64) catch return;
    alloc.free(data);
    data[0] = 1;
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-005") != nil {
		t.Error("did not expect UAF finding on a purely-internal allocation")
	}
}

func TestUseAfterFreeFieldSensitive(t *testing.T) {
	// Freeing tree.source then using sibling tree.deinit() is NOT a use of the
	// freed member — field-sensitivity must suppress this (a real-repo FP shape).
	code := `
pub fn drop(gpa: std.mem.Allocator, tree: *Tree) void {
    gpa.free(tree.source);
    tree.deinit(gpa);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-005") != nil {
		t.Error("did not expect UAF finding for a sibling-member access after free")
	}
}

func TestNoUseAfterFreeWhenNotReused(t *testing.T) {
	code := `
pub fn ok(alloc: std.mem.Allocator) void {
    const data = alloc.alloc(u8, 64) catch return;
    alloc.free(data);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-005") != nil {
		t.Error("did not expect UAF finding when freed value is not reused")
	}
}

func TestDeferFreeIsSafe(t *testing.T) {
	// `defer alloc.free(x)` frees at scope exit, so a later use is well-defined.
	code := `
pub fn ok(alloc: std.mem.Allocator) !void {
    const data = try alloc.alloc(u8, 64);
    defer alloc.free(data);
    data[0] = 1;
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-005") != nil {
		t.Error("did not expect UAF finding for a defer-guarded free")
	}
}

func TestErrdeferFreeIsSafe(t *testing.T) {
	code := `
pub fn ok(alloc: std.mem.Allocator, size: usize) ![]u8 {
    const buf = try alloc.alloc(u8, size);
    errdefer alloc.free(buf);
    @memset(buf, 0);
    return buf;
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-005") != nil {
		t.Error("did not expect UAF finding for an errdefer-guarded free")
	}
}

func TestCommentedHazardNotFlagged(t *testing.T) {
	code := `
pub fn x(buf: []u8) void {
    // const hdr = @ptrCast(buf.ptr);
    _ = buf;
}
`
	if len(scanZig(t, code)) != 0 {
		t.Error("did not expect findings for a commented-out hazard")
	}
}

func TestStringLiteralHazardNotFlagged(t *testing.T) {
	code := `
pub fn x() []const u8 {
    return "use @ptrCast and @memcpy(a[0..n], b)";
}
`
	if len(scanZig(t, code)) != 0 {
		t.Error("did not expect findings for hazard text inside a string literal")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/main.go",
		Content:  "x := @ptrCast(p)",
		Language: rules.LangGo,
	}
	a := &ZigASTAnalyzer{}
	if len(a.Scan(ctx)) != 0 {
		t.Error("expected no findings for non-Zig language")
	}
}

func TestEmptyContent(t *testing.T) {
	if len(scanZig(t, "")) != 0 {
		t.Error("expected no findings for empty content")
	}
}

func TestSafeCode(t *testing.T) {
	code := `
const std = @import("std");
pub fn main() void {
    var x: u32 = 42;
    std.debug.print("{d}\n", .{x});
}
`
	for _, f := range scanZig(t, code) {
		if strings.HasPrefix(f.RuleID, "BATOU-ZIG-AST") {
			t.Errorf("unexpected finding %s on safe code", f.RuleID)
		}
	}
}

func TestDoubleFreeExternal(t *testing.T) {
	// Externally-derived allocation freed twice → double-free (CWE-415).
	code := `
pub fn handle(allocator: std.mem.Allocator, fd: i32) !void {
    const data = try allocator.alloc(u8, 64);
    _ = try std.posix.read(fd, data);
    allocator.free(data);
    allocator.free(data);
}
`
	f := hasRule(scanZig(t, code), "BATOU-ZIG-AST-006")
	if f == nil {
		t.Fatal("expected double-free finding on externally-derived allocation")
	}
	if f.CWEID != "CWE-415" {
		t.Errorf("expected CWE-415, got %s", f.CWEID)
	}
}

func TestDoubleFreeRebindNoFP(t *testing.T) {
	// free; reassign; free → NOT a double-free (rebind ends the freed lifetime).
	code := `
pub fn handle(allocator: std.mem.Allocator, fd: i32) !void {
    var data = try allocator.alloc(u8, 64);
    _ = try std.posix.read(fd, data);
    allocator.free(data);
    data = try allocator.alloc(u8, 32);
    allocator.free(data);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-006") != nil {
		t.Error("free+rebind+free must NOT be a double-free")
	}
}

func TestDoubleFreeInternalNoFP(t *testing.T) {
	// Internally-allocated (no external origin) freed twice → gated out (no flood).
	code := `
pub fn f(allocator: std.mem.Allocator) !void {
    const data = try allocator.alloc(u8, 64);
    allocator.free(data);
    allocator.free(data);
}
`
	if hasRule(scanZig(t, code), "BATOU-ZIG-AST-006") != nil {
		t.Error("internal-origin double-free must be gated out by the external-origin gate")
	}
}
