import Vapor
import SQLite3

func handler017(_ req: Request) throws -> String {
    let query = "SELECT COUNT(*) FROM users WHERE active = 1"
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, query, nil, nil, nil)
    return "counted"
}
