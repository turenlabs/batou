import Vapor
import Foundation

func handler074(_ req: Request) throws -> Response {
    let name = try req.parameters.require("name")
    let base = "/var/data/files"
    let fullPath = (base + "/" + name) as NSString
    let resolved = fullPath.resolvingSymlinksInPath
    guard resolved.hasPrefix(base) else { throw Abort(.forbidden) }
    let data = FileManager.default.contents(atPath: resolved)
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
