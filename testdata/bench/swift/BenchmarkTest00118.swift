import Vapor

func handler118(_ req: Request) throws -> Response {
    let returnUrl: String = try req.query.get(at: "return")
    guard returnUrl.starts(with: "/") && !returnUrl.starts(with: "//") else {
        return req.redirect(to: "/home")
    }
    return req.redirect(to: returnUrl)
}
