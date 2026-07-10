import Vapor
import Fluent

func handler012(_ req: Request) throws -> EventLoopFuture<[User]> {
    let name: String = try req.query.get(at: "name")
    return User.query(on: req.db)
        .filter(\.$name == name)
        .all()
}
