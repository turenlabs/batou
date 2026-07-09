import Vapor

func handler114(_ req: Request) throws -> Response {
    let page = try req.parameters.require("page")
    guard !page.contains("://") && !page.contains("..") else { throw Abort(.forbidden) }
    return req.redirect(to: "https://myapp.com/" + page)
}
