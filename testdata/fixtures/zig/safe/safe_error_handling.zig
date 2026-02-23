const std = @import("std");

// SAFE: Using try to propagate errors
pub fn parseNumber(input: []const u8) !u32 {
    return try std.fmt.parseInt(u32, input, 10);
}

// SAFE: catch with explicit error handling
pub fn openFileOrDefault(path: []const u8) std.fs.File {
    return std.fs.cwd().openFile(path, .{}) catch |err| {
        std.log.warn("failed to open {s}: {}", .{ path, err });
        return std.fs.cwd().openFile("default.conf", .{}) catch |e| {
            std.log.err("fallback also failed: {}", .{e});
            @panic("cannot open any config file");
        };
    };
}

// SAFE: Using orelse with a default value
pub fn getEnvOrDefault(key: []const u8) []const u8 {
    return std.process.getEnvVarOwned(std.heap.page_allocator, key) catch |_| {
        return "default_value";
    };
}

// SAFE: Pattern matching on error
pub fn connectToService(host: []const u8, port: u16) !std.net.Stream {
    return std.net.tcpConnectToHost(host, port) catch |err| switch (err) {
        error.ConnectionRefused => {
            std.log.err("service unavailable at {s}:{d}", .{ host, port });
            return error.ServiceUnavailable;
        },
        error.NetworkUnreachable => {
            std.log.err("network unreachable", .{});
            return error.NetworkDown;
        },
        else => return err,
    };
}

// SAFE: Proper resource cleanup with errdefer
pub fn allocateBuffer(allocator: std.mem.Allocator, size: usize) ![]u8 {
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);

    // Initialize buffer
    @memset(buf, 0);
    return buf;
}
