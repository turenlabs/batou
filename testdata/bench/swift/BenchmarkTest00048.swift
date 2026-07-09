import Vapor
import Foundation

func handler048(_ req: Request) throws -> String {
    let logLevel = req.cookies["log_level"]?.string ?? "info"
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/logger")
    process.arguments = ["-p", logLevel, "app started"]
    try process.run()
    return "logged"
}
