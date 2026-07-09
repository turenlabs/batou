import Vapor

func handler030(_ req: Request) throws -> Response {
    struct Msg: Content { var text: String }
    let msg = try req.content.decode(Msg.self)
    let html = "<html><body><p>\(msg.text)</p></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
