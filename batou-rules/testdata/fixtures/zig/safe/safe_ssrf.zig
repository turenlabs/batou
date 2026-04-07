const std = @import("std");

// Safe: hardcoded URL, no SSRF risk
pub fn fetchConfig(allocator: std.mem.Allocator) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const result = try client.fetch(.{
        .url = "https://api.internal.example.com/config",
    });
    _ = result;
}

// Safe: URL validated with allowlist prefix check
pub fn safeProxy(allocator: std.mem.Allocator, user_url: []const u8) !void {
    if (!std.mem.startsWith(u8, user_url, "https://allowed.example.com/")) return;

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const result = try client.fetch(.{
        .url = user_url,
    });
    _ = result;
}

// Safe: Numeric input clamped before use
pub fn safeIndex(user_input: []const u8) !usize {
    const raw = try std.fmt.parseInt(usize, user_input, 10);
    return std.math.clamp(raw, 0, 1024);
}

// Safe: File extension validated via endsWith
pub fn safeFileCheck(filename: []const u8) bool {
    return std.mem.endsWith(u8, filename, ".txt") or std.mem.endsWith(u8, filename, ".csv");
}
