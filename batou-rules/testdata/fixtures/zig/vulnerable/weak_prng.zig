const std = @import("std");

// CWE-338: Weak PRNG used for session token generation
fn generateSessionToken() [32]u8 {
    var prng = std.rand.DefaultPrng.init(42);
    const rand = prng.random();
    var token: [32]u8 = undefined;
    for (&token) |*byte| {
        byte.* = rand.int(u8);
    }
    return token;
}

// CWE-338: Isaac64 PRNG for security-sensitive use
fn generateApiKey(allocator: std.mem.Allocator) []u8 {
    var rng = std.rand.Isaac64.init(0);
    var key = allocator.alloc(u8, 32) catch unreachable;
    for (key) |*byte| {
        byte.* = rng.random().int(u8);
    }
    return key;
}
