const std = @import("std");

// ZIG-006: catch unreachable on fallible operation
pub fn parseInput(input: []const u8) u32 {
    return std.fmt.parseInt(u32, input, 10) catch unreachable;
}

// ZIG-006: catch unreachable on file open
pub fn mustOpenFile(path: []const u8) std.fs.File {
    return std.fs.cwd().openFile(path, .{}) catch unreachable;
}

// ZIG-006: catch |_| undefined suppresses errors with UB
pub fn dangerousRead(buf: []u8) []u8 {
    const file = std.fs.cwd().openFile("/etc/config", .{}) catch |_| undefined;
    return file.readAll(buf) catch |_| undefined;
}

// ZIG-006: catch unreachable on network operation
pub fn mustConnect(addr: []const u8) std.net.Stream {
    return std.net.tcpConnectToHost(addr, 8080) catch unreachable;
}

// ZIG-006: catch unreachable on allocation
pub fn mustAllocate(allocator: std.mem.Allocator, size: usize) []u8 {
    return allocator.alloc(u8, size) catch unreachable;
}
