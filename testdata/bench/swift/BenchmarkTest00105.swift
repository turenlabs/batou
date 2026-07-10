import Vapor

func handler105(_ req: Request) throws -> Response {
    let returnUrl = req.cookies["return_url"]?.string ?? "/"
    return req.redirect(to: returnUrl)
}
