import Vapor
import Foundation

func handler075(_ req: Request) throws -> Response {
    let file = try req.parameters.require("file")
    let allowed = ["readme.txt", "license.txt", "changelog.txt"]
    guard allowed.contains(file) else { throw Abort(.notFound) }
    let data = FileManager.default.contents(atPath: "/docs/" + file)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
