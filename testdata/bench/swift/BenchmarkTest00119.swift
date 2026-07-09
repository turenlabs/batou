import Vapor

enum Destination: String, Content { case home, profile, settings }

func handler119(_ req: Request) throws -> Response {
    let dest = try req.content.decode(Destination.self)
    let paths: [Destination: String] = [.home: "/", .profile: "/profile", .settings: "/settings"]
    return req.redirect(to: paths[dest] ?? "/")
}
