import Vapor
import Foundation

func handler062(_ req: Request) throws -> Response {
    let filePath: String = try req.query.get(at: "file")
    let url = URL(fileURLWithPath: filePath)
    let data = try Data(contentsOf: url)
    return Response(status: .ok, body: .init(data: data))
}
