const std = @import("std");

// ZIG-004: Command injection via std.process.Child with user input
pub fn runUserCommand(allocator: std.mem.Allocator, user_cmd: []const u8) !void {
    var child = std.process.Child.init(.{
        .argv = &[_][]const u8{ "/bin/sh", "-c", user_cmd },
        .allocator = allocator,
    });
    _ = try child.spawnAndWait();
}

// ZIG-004: Direct execve with user-controlled path
pub fn execProgram(path: []const u8) !void {
    return std.os.execve(path, &[_][]const u8{}, &[_][]const u8{});
}

// ZIG-004: std.ChildProcess with dynamic arguments
pub fn spawnWithArgs(allocator: std.mem.Allocator, program: []const u8, args: []const []const u8) !void {
    var child = std.ChildProcess.init(args, allocator);
    child.argv[0] = program;
    _ = try child.spawnAndWait();
}
