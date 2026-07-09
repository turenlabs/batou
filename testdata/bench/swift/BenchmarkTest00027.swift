import Vapor

func handler027(_ req: Request) throws -> Response {
    let comment = req.body.string ?? ""
    let html = "<div class='comment'>\(comment)</div>"
    return Response(status: .ok, body: .init(string: html))
}
