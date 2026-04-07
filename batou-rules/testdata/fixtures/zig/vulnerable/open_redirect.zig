const std = @import("std");

// Open redirect via tainted Location header
pub fn handleLogin(response: *std.http.Server.Response, redirect_url: []const u8) !void {
    response.status = .found;
    response.headers.append("Location", redirect_url);
    try response.do();
}

// Open redirect via respond with tainted extra_headers
pub fn redirectUser(response: *std.http.Server.Response, target: []const u8) !void {
    try response.respond("", .{
        .status = .moved_permanently,
        .extra_headers = &.{.{ .name = "Location", .value = target }},
    });
}
