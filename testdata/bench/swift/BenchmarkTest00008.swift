import Vapor
import SQLite3

func handler008(_ req: Request) throws -> String {
    let apiKey = req.headers.first(name: "X-API-Key") ?? ""
    let query = "SELECT * FROM tokens WHERE key = '\(apiKey)'"
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, query, nil, nil, nil)
    return "verified"
}
