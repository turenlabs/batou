import Vapor
import SQLite3

func handler007(_ req: Request) throws -> EventLoopFuture<String> {
    struct Form: Content { var category: String }
    let form = try req.content.decode(Form.self)
    let sql = "INSERT INTO logs (category) VALUES ('\(form.category)')"
    var db: OpaquePointer?
    sqlite3_open("/tmp/app.db", &db)
    sqlite3_exec(db, sql, nil, nil, nil)
    return req.eventLoop.makeSucceededFuture("logged")
}
