import Vapor
import Foundation

func handler088(_ req: Request) throws -> String {
    let encoded: String = try req.query.get(at: "config")
    guard let data = Data(base64Encoded: encoded) else { throw Abort(.badRequest) }
    let config = try PropertyListDecoder().decode([String: String].self, from: data)
    return config["name"] ?? "unknown"
}
