import Vapor
import Foundation

func handler082(_ req: Request) throws -> Response {
    let data = req.body.data ?? Data()
    let json = try JSONSerialization.jsonObject(with: data, options: .mutableContainers)
    guard let dict = json as? [String: Any] else { throw Abort(.badRequest) }
    let command = dict["cmd"] as? String ?? ""
    let process = Process()
    process.launchPath = command
    try process.run()
    return Response(status: .ok)
}
