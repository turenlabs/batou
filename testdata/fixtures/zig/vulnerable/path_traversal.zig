const std = @import("std");

// ZIG-005: Path traversal via string concatenation with fs.openFile
pub fn readUserFile(user_path: []const u8) ![]u8 {
    const base = "/data/uploads/";
    const full_path = base ++ "/" ++ user_path;
    const file = std.fs.openFile(full_path, .{});
    _ = file;
    return undefined;
}

// ZIG-005: Path traversal via allocPrint + openFile
pub fn readFormattedPath(allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "/var/www/static/{s}", .{filename});
    defer allocator.free(path);
    const file = std.fs.openFile(path, .{});
    _ = file;
    return undefined;
}

// ZIG-005: Dir.openFile with concatenated path
pub fn openFromDir(dir: std.fs.Dir, user_input: []const u8) !std.fs.File {
    const subpath = "/uploads/" ++ user_input;
    return Dir.openFile(subpath, .{});
}
