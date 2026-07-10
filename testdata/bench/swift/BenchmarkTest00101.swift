import Vapor

func handler101(_ req: Request) throws -> Response {
    let url: String = try req.query.get(at: "url")
    return req.redirect(to: url)
}
