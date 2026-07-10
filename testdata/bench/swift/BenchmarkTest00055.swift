import Vapor
import Foundation

func handler055(_ req: Request) throws -> String {
    let host: String = try req.query.get(at: "host")
    let regex = try NSRegularExpression(pattern: "^[a-zA-Z0-9.-]+$")
    let range = NSRange(host.startIndex..., in: host)
    guard regex.firstMatch(in: host, range: range) != nil else { throw Abort(.badRequest) }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/sbin/ping")
    process.arguments = ["-c", "1", host]
    try process.run()
    return "pinged"
}
