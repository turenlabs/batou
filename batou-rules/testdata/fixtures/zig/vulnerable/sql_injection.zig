const std = @import("std");
const sqlite = @import("sqlite");

// SQL injection via string concatenation into exec
pub fn findUser(db: *sqlite.Db, allocator: std.mem.Allocator, username: []const u8) !void {
    const query = try std.fmt.allocPrint(allocator, "SELECT * FROM users WHERE name = '{s}'", .{username});
    defer allocator.free(query);
    _ = try db.exec(query, .{});
}

// SQL injection via dynamic prepare
pub fn deleteRecord(db: *sqlite.Db, allocator: std.mem.Allocator, table: []const u8) !void {
    const query = try std.fmt.allocPrint(allocator, "DELETE FROM {s} WHERE id = 1", .{table});
    defer allocator.free(query);
    var stmt = try db.prepare(query);
    defer stmt.deinit();
}
