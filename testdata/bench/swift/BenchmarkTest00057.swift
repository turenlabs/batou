import Vapor
import Foundation

func handler057(_ req: Request) throws -> Response {
    let filename = try req.parameters.require("file")
    let safeDir = URL(fileURLWithPath: "/var/data/public/")
    let fileURL = safeDir.appendingPathComponent(filename).standardizedFileURL
    guard fileURL.path.hasPrefix(safeDir.path) else { throw Abort(.forbidden) }
    let data = try Data(contentsOf: fileURL)
    return Response(status: .ok, body: .init(data: data))
}
