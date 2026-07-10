import Vapor
import SQLite3

func handler002(_ req: Request) throws -> String {
    let name: String = try req.query.get(at: "name")
    let query = "SELECT * FROM users WHERE name = '" + name + "'"
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, query, nil, nil, nil)
    return "ok"
}
