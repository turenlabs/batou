import Vapor
import Foundation

func handler077(_ req: Request) throws -> Response {
    let filename = try req.parameters.require("file")
    guard !filename.contains("..") && !filename.contains("/") else { throw Abort(.forbidden) }
    let data = FileManager.default.contents(atPath: "/public/" + filename)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
