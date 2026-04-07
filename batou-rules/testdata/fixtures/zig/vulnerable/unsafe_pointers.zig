const std = @import("std");

// ZIG-001: Unsafe @ptrCast to change pointer type
pub fn castPointer(raw: *const u8) *const u32 {
    return @ptrCast(*const u32, raw);
}

// ZIG-001: @ptrCast on a slice pointer
pub fn castSlice(bytes: [*]const u8) [*]const u64 {
    return @ptrCast([*]const u64, bytes);
}

// ZIG-002: @intToPtr from arbitrary integer
pub fn addressToPointer(addr: usize) *volatile u32 {
    return @intToPtr(*volatile u32, addr);
}

// ZIG-002: @intToPtr with hardcoded address
pub fn mmioRegister() *volatile u8 {
    return @intToPtr(*volatile u8, 0x4000_0000);
}

// ZIG-003: @alignCast to assert alignment
pub fn forceAlign(raw: *align(1) const u8) *align(4) const u8 {
    return @alignCast(@alignOf(u32), raw);
}

// ZIG-007: @bitCast to reinterpret float as integer
pub fn floatBits(f: f32) u32 {
    return @bitCast(u32, f);
}

// ZIG-007: @bitCast on a pointer
pub fn reinterpretPointer(ptr: *const u32) *const f32 {
    return @bitCast(*const f32, ptr);
}

// ZIG-008: Weak crypto using MD5
pub fn md5Hash(data: []const u8) [16]u8 {
    var hasher = std.crypto.hash.Md5.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

// ZIG-008: Weak crypto using SHA1
pub fn sha1Hash(data: []const u8) [20]u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}
