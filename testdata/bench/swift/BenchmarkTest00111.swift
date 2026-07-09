import Vapor

func handler111(_ req: Request) throws -> Response {
    return req.redirect(to: "/dashboard")
}
