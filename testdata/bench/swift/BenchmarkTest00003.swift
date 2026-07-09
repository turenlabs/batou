import Vapor
import GRDB

func handler003(_ req: Request) throws -> EventLoopFuture<String> {
    let search = try req.content.decode(SearchInput.self).term
    let dbPool = req.application.db as! DatabasePool
    try dbPool.write { db in
        try db.execute(sql: "DELETE FROM items WHERE name = '\(search)'")
    }
    return req.eventLoop.makeSucceededFuture("deleted")
}
struct SearchInput: Content { var term: String }
