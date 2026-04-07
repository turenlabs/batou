const std = @import("std");

// SSRF via std.http.Client.fetch with user-controlled URL
pub fn fetchUrl(allocator: std.mem.Allocator, user_url: []const u8) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();

    _ = try client.fetch(.{
        .url = user_url,
        .response_storage = .{ .dynamic = &body },
    });
}

// SSRF via std.net.tcpConnectToHost with user-controlled hostname
pub fn connectToHost(allocator: std.mem.Allocator, host: []const u8) !void {
    const stream = try std.net.tcpConnectToHost(allocator, host, 80);
    defer stream.close();
    _ = try stream.read(&[_]u8{0} ** 1024);
}

// SSRF via DNS resolution with user-controlled hostname
pub fn resolveHost(host: []const u8) !void {
    const addr = try std.net.Address.resolveIp(host, 80);
    _ = addr;
}
