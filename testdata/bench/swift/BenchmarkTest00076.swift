import Vapor
import Foundation

func handler076(_ req: Request) throws -> Response {
    let rawId = try req.parameters.require("id")
    guard let _ = UUID(uuidString: rawId) else { throw Abort(.badRequest) }
    let path = "/uploads/" + rawId + ".pdf"
    let data = FileManager.default.contents(atPath: path)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
