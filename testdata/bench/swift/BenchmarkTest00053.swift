import Vapor
import Foundation

func handler053(_ req: Request) throws -> String {
    let rawCount = try req.parameters.require("count")
    guard let count = Int(rawCount), count > 0, count <= 100 else { throw Abort(.badRequest) }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/head")
    process.arguments = ["-n", String(count), "/var/log/app.log"]
    try process.run()
    return "ok"
}
