import Vapor

func handler102(_ req: Request) throws -> Response {
    let target = try req.parameters.require("target")
    return req.redirect(to: target)
}
