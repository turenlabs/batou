import Vapor
import SQLite3

func handler001(_ req: Request) throws -> String {
    let userId = try req.parameters.require("id")
    let query = "SELECT * FROM users WHERE id = '\(userId)'"
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, query, nil, nil, nil)
    return "ok"
}
