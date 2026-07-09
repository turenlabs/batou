// Safe Zig memory-safety counterparts: should NOT trigger zigast findings.
const std = @import("std");

// Comptime-literal-bounded copy: dst and src lengths are statically equal.
pub fn fixedCopy(dst: []u8, src: []const u8) void {
    @memcpy(dst[0..16], src[0..16]);
}

// Allocation freed exactly once at end of lifetime; never reused.
pub fn cleanAlloc(alloc: std.mem.Allocator) !void {
    const data = try alloc.alloc(u8, 64);
    defer alloc.free(data);
    data[0] = 1;
}

// Plain scalar work, no casts or raw memory ops.
pub fn add(a: u32, b: u32) u32 {
    return a + b;
}
