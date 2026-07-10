import Vapor
import SQLite3

func handler016(_ req: Request) throws -> String {
    let rawId = try req.parameters.require("id")
    guard let numericId = Int(rawId) else { throw Abort(.badRequest) }
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, "SELECT * FROM users WHERE id = \(numericId)", nil, nil, nil)
    return "ok"
}
