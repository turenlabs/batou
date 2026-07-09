import Vapor
import SQLite3

func handler006(_ req: Request) throws -> String {
    let param = try req.parameters.require("search")
    var db: OpaquePointer?
    var stmt: OpaquePointer?
    sqlite3_open(":memory:", &db)
    let sql = "SELECT name FROM products WHERE description LIKE '%\(param)%'"
    sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
    return "ok"
}
