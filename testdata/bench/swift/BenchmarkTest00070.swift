import Vapor
import Foundation

func handler070(_ req: Request) throws -> Response {
    let resource: String = try req.query.get(at: "resource")
    let url = URL(fileURLWithPath: "/public/" + resource)
    let content = try String(contentsOf: url, encoding: .utf8)
    return Response(status: .ok, body: .init(string: content))
}
