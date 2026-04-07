// Source: CWE-78 - OS Command Injection via ChildProcess in Zig
// Expected: BATOU-ZIG
// OWASP: A03:2021 - Injection (Command Injection)

const std = @import("std");

pub fn runCommand(user_input: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const cmd = try std.fmt.allocPrint(allocator, "ping -c 1 {s}", .{user_input});
    var child = std.process.Child.init(.{
        .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
    }, allocator);
    _ = try child.spawnAndWait();
}

pub fn main() !void {
    var args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    if (args.len > 1) {
        try runCommand(args[1]);
    }
}
