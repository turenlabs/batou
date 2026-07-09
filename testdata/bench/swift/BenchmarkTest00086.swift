import Vapor
import Foundation

func handler086(_ req: Request) throws -> String {
    let rawData = req.body.data ?? Data()
    let json = try JSONSerialization.jsonObject(with: rawData, options: [])
    guard let config = json as? [String: Any] else { throw Abort(.badRequest) }
    if let eval = config["eval"] as? String {
        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", eval]
        try process.run()
    }
    return "processed"
}
