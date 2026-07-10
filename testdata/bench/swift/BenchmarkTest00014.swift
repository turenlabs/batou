import Vapor
import FMDB

func handler014(_ req: Request) throws -> String {
    let email = req.body.string ?? ""
    let db = FMDatabase(path: "/tmp/test.db")
    db.open()
    let rs = db.executeQuery("SELECT * FROM accounts WHERE email = ?", withArgumentsIn: [email])
    return "found"
}
