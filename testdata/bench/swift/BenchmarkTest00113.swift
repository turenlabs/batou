import Vapor

func handler113(_ req: Request) throws -> Response {
    let path: String = try req.query.get(at: "path")
    guard path.hasPrefix("/") && !path.hasPrefix("//") else { throw Abort(.badRequest) }
    return req.redirect(to: path)
}
