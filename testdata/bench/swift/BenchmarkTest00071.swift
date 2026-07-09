import Vapor
import Foundation

func handler071(_ req: Request) throws -> Response {
    let filename = try req.parameters.require("file")
    let baseDir = URL(fileURLWithPath: "/var/data/public/")
    let fileURL = baseDir.appendingPathComponent(filename).standardizedFileURL
    guard fileURL.path.hasPrefix(baseDir.path) else { throw Abort(.forbidden) }
    let data = try Data(contentsOf: fileURL)
    return Response(status: .ok, body: .init(data: data))
}
