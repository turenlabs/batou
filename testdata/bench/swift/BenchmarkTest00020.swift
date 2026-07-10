import Vapor
import GRDB

func handler020(_ req: Request) throws -> String {
    let dbPool = req.application.db as! DatabasePool
    try dbPool.write { db in
        try db.execute(sql: "DELETE FROM expired_sessions WHERE created_at < datetime('now', '-30 days')")
    }
    return "cleaned"
}
