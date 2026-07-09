import Vapor

func handler112(_ req: Request) throws -> Response {
    let url: String = try req.query.get(at: "url")
    let allowedHosts = ["example.com", "app.example.com"]
    guard let parsed = URL(string: url), let host = parsed.host,
          allowedHosts.contains(host) else {
        throw Abort(.forbidden)
    }
    return req.redirect(to: url)
}
