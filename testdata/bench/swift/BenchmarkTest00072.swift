import Vapor
import Foundation

func handler072(_ req: Request) throws -> Response {
    let filename = try req.parameters.require("file")
    let safe = (filename as NSString).lastPathComponent
    let path = "/uploads/" + safe
    let data = FileManager.default.contents(atPath: path)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
