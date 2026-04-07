const std = @import("std");

// Weak MD5 hash used for password verification
pub fn hashPassword(password: []const u8) [16]u8 {
    var hasher = std.crypto.hash.Md5.init(.{});
    hasher.update(password);
    return hasher.finalResult();
}

// Weak SHA-1 hash used for token generation
pub fn generateToken(data: []const u8) [20]u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}
