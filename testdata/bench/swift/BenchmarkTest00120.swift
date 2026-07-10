import Vapor

func handler120(_ req: Request) throws -> Response {
    let rawId = try req.parameters.require("id")
    guard let id = Int(rawId) else { throw Abort(.badRequest) }
    return req.redirect(to: "/users/\(id)")
}
