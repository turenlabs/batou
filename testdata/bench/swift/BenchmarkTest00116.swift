import Vapor

func handler116(_ req: Request) throws -> Response {
    return req.redirect(to: "/login")
}
