import Vapor

func handler109(_ req: Request) throws -> Response {
    let path: String = try req.query.get(at: "path")
    return req.redirect(to: "https://example.com" + path)
}
