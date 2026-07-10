import Vapor
import SQLite3

func handler011(_ req: Request) throws -> String {
    let userId = try req.parameters.require("id")
    var db: OpaquePointer?
    var stmt: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, nil)
    sqlite3_bind_text(stmt, 1, userId, -1, nil)
    return "ok"
}
