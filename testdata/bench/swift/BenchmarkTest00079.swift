import Vapor
import Foundation

func handler079(_ req: Request) throws -> Response {
    let rawId = try req.parameters.require("id")
    guard let id = Int(rawId) else { throw Abort(.badRequest) }
    let path = "/data/records/\(id).json"
    let data = FileManager.default.contents(atPath: path)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
