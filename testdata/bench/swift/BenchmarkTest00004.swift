import Vapor
import FMDB

func handler004(_ req: Request) throws -> String {
    let email = req.body.string ?? ""
    let db = FMDatabase(path: "/tmp/test.db")
    db.open()
    let query = "SELECT * FROM accounts WHERE email = '\(email)'"
    let rs = db.executeQuery(query, withArgumentsIn: [])
    return "found"
}
