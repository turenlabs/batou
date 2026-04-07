// Source: CWE-22 - Path Traversal via std.fs file operations in Zig
// Expected: BATOU-ZIG
// OWASP: A01:2021 - Broken Access Control (Path Traversal)

const std = @import("std");

pub fn readUserFile(filename: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const path = try std.fmt.allocPrint(allocator, "/var/uploads/{s}", .{filename});
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 1024 * 1024);
}

pub fn main() !void {
    var args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    if (args.len > 1) {
        const data = try readUserFile(args[1]);
        const stdout = std.io.getStdOut().writer();
        try stdout.writeAll(data);
    }
}
