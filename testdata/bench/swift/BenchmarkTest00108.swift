import Vapor

func handler108(_ req: Request) throws -> Response {
    let url = req.body.string ?? "/"
    return req.redirect(to: url)
}
