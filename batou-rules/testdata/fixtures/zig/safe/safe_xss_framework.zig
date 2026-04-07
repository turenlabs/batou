const std = @import("std");
const zap = @import("zap");
const httpz = @import("httpz");

// Safe: HTML-escaped output via zap
fn handleZapSafe(r: zap.Request) void {
    const name = r.getParamSlice("name");
    if (name) |n| {
        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        std.html.escape(stream.writer(), n);
        r.sendBody(stream.getWritten()) catch return;
    }
}

// Safe: validated integer param in SQL (no injection)
fn handleSqlSafe(req: *httpz.Request, res: *httpz.Response) void {
    const id_str = req.param("id");
    if (id_str) |s| {
        const id = std.fmt.parseInt(u64, s, 10) catch return;
        _ = id;
        // Use parameterized query with bind
        var stmt = db.prepare("SELECT * FROM users WHERE id = ?") catch return;
        stmt.bind(.{id}) catch return;
    }
    _ = res;
}

// Safe: path canonicalized before file read
fn handleFileReadSafe(req: *httpz.Request, res: *httpz.Response) void {
    const body = req.body();
    if (body) |path| {
        const basename = std.fs.path.basename(path);
        const dir = std.fs.cwd() catch return;
        const real = dir.realpathAlloc(allocator, basename) catch return;
        if (std.mem.startsWith(u8, real, "/srv/public/")) {
            const file = dir.openFile(real, .{}) catch return;
            defer file.close();
            const content = file.readAllAlloc(allocator, 1024 * 1024) catch return;
            res.writeAll(content) catch return;
        }
    }
}
