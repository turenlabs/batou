import Vapor

func handler117(_ req: Request) throws -> Response {
    let url: String = try req.query.get(at: "url")
    guard let parsed = URL(string: url), parsed.host == "example.com" else {
        return req.redirect(to: "/")
    }
    return req.redirect(to: url)
}
