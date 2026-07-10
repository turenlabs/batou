import Vapor
import Foundation

func handler061(_ req: Request) throws -> Response {
    let path = try req.parameters.require("path")
    let data = FileManager.default.contents(atPath: path)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
