import Vapor
import Foundation

func handler049(_ req: Request) throws -> String {
    let dir: String = try req.query.get(at: "dir")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", "ls -la " + dir]
    try process.run()
    return "listed"
}
