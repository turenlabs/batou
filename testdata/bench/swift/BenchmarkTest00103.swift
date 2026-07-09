import Vapor

func handler103(_ req: Request) throws -> Response {
    struct RedirectInput: Content { var redirectUrl: String }
    let input = try req.content.decode(RedirectInput.self)
    return req.redirect(to: input.redirectUrl)
}
