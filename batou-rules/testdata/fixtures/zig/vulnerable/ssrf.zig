const std = @import("std");

// SSRF via std.http.Client.fetch with user-controlled URL
pub fn proxyRequest(allocator: std.mem.Allocator, user_url: []const u8) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const result = try client.fetch(.{
        .url = user_url,
    });
    _ = result;
}

// SSRF via std.http.Client.open with tainted URI
pub fn openConnection(allocator: std.mem.Allocator, target: []const u8) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(target);
    var req = try client.open(.GET, uri, .{
        .allocator = allocator,
    });
    defer req.deinit();
}
