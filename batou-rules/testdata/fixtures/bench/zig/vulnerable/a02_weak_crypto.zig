// Source: CWE-327 - Use of weak Md5 hash in Zig
// Expected: BATOU-ZIG
// OWASP: A02:2021 - Cryptographic Failures

const std = @import("std");

pub fn hashPassword(password: []const u8) [32]u8 {
    var hash: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    std.crypto.hash.Md5.hash(password, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

pub fn main() !void {
    const result = hashPassword("admin123");
    const stdout = std.io.getStdOut().writer();
    try stdout.print("MD5: {s}\n", .{&result});
}
