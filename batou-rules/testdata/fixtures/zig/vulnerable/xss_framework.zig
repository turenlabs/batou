const std = @import("std");
const zap = @import("zap");
const httpz = @import("httpz");

// XSS via zap: user query param reflected in response body
fn handleZap(r: zap.Request) void {
    const name = r.getParamSlice("name");
    if (name) |n| {
        r.sendBody(n) catch return;
    }
}

// XSS via httpz: user param reflected in response
fn handleHttpz(req: *httpz.Request, res: *httpz.Response) void {
    const q = req.query() catch return;
    const search = q.get("q");
    if (search) |s| {
        res.writeAll(s) catch return;
    }
}

// SQL injection via httpz: route param in query
fn handleSqlInjection(req: *httpz.Request, res: *httpz.Response) void {
    const id = req.param("id");
    if (id) |user_id| {
        const query = std.fmt.allocPrint(allocator, "SELECT * FROM users WHERE id = '{s}'", .{user_id}) catch return;
        db.exec(query) catch return;
    }
    _ = res;
}

// Path traversal via httpz body
fn handleFileRead(req: *httpz.Request, res: *httpz.Response) void {
    const body = req.body();
    if (body) |path| {
        const dir = std.fs.cwd() catch return;
        const file = dir.openFile(path, .{}) catch return;
        defer file.close();
        const content = file.readAllAlloc(allocator, 1024 * 1024) catch return;
        res.writeAll(content) catch return;
    }
}
