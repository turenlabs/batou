const std = @import("std");

// SAFE: Opening a static known file path
pub fn readConfig() ![]u8 {
    const file = try std.fs.cwd().openFile("config.json", .{});
    defer file.close();
    return file.readToEndAlloc(std.heap.page_allocator, 1024 * 1024);
}

// SAFE: Using realpathZ to resolve and validate path
pub fn safeReadFile(allocator: std.mem.Allocator, user_path: []const u8) ![]u8 {
    const resolved = try std.fs.realpathZ(user_path);
    const base = "/data/uploads/";
    if (!std.mem.startsWith(u8, &resolved, base)) {
        return error.PathTraversal;
    }
    const file = try std.fs.openFile(&resolved, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, 1024 * 1024);
}

// SAFE: Reading from a well-known directory with static subpath
pub fn readStaticAsset() ![]u8 {
    var dir = try std.fs.cwd().openDir("static", .{});
    defer dir.close();
    const file = try dir.openFile("index.html", .{});
    defer file.close();
    return file.readToEndAlloc(std.heap.page_allocator, 1024 * 1024);
}

// SAFE: Writing to a temp file with no user input in path
pub fn writeTempData(data: []const u8) !void {
    const file = try std.fs.cwd().createFile("/tmp/app_output.dat", .{});
    defer file.close();
    try file.writeAll(data);
}
