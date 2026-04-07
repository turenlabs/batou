const std = @import("std");

// SAFE: Using @as for safe numeric cast
pub fn safeCast(x: u16) u32 {
    return @as(u32, x);
}

// SAFE: Using @intCast for checked integer cast
pub fn safeIntCast(x: u64) u32 {
    return @intCast(u32, x);
}

// SAFE: Using slicing instead of pointer cast
pub fn safeSlice(data: []const u8) []const u8 {
    return data[0..4];
}

// SAFE: Using std.mem.bytesAsSlice for safe reinterpretation
pub fn safeBytesToSlice(bytes: []const u8) []const u32 {
    return std.mem.bytesAsSlice(u32, bytes);
}

// SAFE: Arithmetic operations without pointer manipulation
pub fn compute(a: u32, b: u32) u64 {
    const wide_a = @as(u64, a);
    const wide_b = @as(u64, b);
    return wide_a * wide_b;
}

// SAFE: Using std.crypto.hash.sha2.Sha256 (strong hash)
pub fn sha256Hash(data: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}
