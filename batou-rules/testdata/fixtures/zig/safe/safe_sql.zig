const std = @import("std");
const sqlite = @import("sqlite");

// Safe: parameterized query with bind
pub fn findUserSafe(db: *sqlite.Db, username: []const u8) !void {
    var stmt = try db.prepare("SELECT * FROM users WHERE name = ?");
    defer stmt.deinit();
    stmt.bind(.{username});
    _ = try stmt.step();
}

// Safe: hardcoded query, no user input in SQL
pub fn countUsers(db: *sqlite.Db) !void {
    _ = try db.exec("SELECT COUNT(*) FROM users", .{});
}
