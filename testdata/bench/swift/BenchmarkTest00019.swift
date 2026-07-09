import Vapor
import Fluent

func handler019(_ req: Request) throws -> EventLoopFuture<HTTPStatus> {
    let input = try req.content.decode(CreateUser.self)
    let user = User(name: input.name, email: input.email)
    return user.save(on: req.db).transform(to: .created)
}
struct CreateUser: Content { var name: String; var email: String }
