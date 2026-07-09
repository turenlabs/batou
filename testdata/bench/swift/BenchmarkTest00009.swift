import Vapor
import GRDB

func handler009(_ req: Request) throws -> String {
    let session = req.cookies["session"]?.string ?? ""
    let dbPool = req.application.db as! DatabasePool
    try dbPool.read { db in
        let row = try Row.fetchOne(db, sql: "SELECT * FROM sessions WHERE token = '\(session)'")
    }
    return "ok"
}
