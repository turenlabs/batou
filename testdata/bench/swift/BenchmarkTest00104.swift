import Vapor

func handler104(_ req: Request) throws -> Response {
    let referer = req.headers.first(name: "Referer") ?? "/"
    return req.redirect(to: referer)
}
