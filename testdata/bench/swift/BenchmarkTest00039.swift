import Vapor

func handler039(_ req: Request) throws -> Response {
    let rawId = try req.parameters.require("id")
    guard let id = Int(rawId) else { throw Abort(.badRequest) }
    let html = "<html><body><p>User ID: \(id)</p></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
