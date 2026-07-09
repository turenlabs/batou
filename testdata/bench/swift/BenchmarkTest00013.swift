import Vapor
import GRDB

func handler013(_ req: Request) throws -> String {
    let search = try req.content.decode(SearchInput.self).term
    let dbPool = req.application.db as! DatabasePool
    try dbPool.read { db in
        let rows = try Row.fetchAll(db, sql: "SELECT * FROM items WHERE name = ?", arguments: [search])
    }
    return "found"
}
struct SearchInput: Content { var term: String }
