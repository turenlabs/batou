import Vapor
import SQLite3

func handler010(_ req: Request) throws -> String {
    let sortBy: String = try req.query.get(at: "sort")
    let direction = req.query[String.self, at: "dir"] ?? "ASC"
    let query = "SELECT * FROM products ORDER BY \(sortBy) \(direction)"
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, query, nil, nil, nil)
    return "sorted"
}
