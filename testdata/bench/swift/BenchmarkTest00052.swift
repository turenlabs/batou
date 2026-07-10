import Vapor
import Foundation

func handler052(_ req: Request) throws -> String {
    let cmd = try req.parameters.require("cmd")
    let allowedCommands = ["status", "version", "health"]
    guard allowedCommands.contains(cmd) else { throw Abort(.forbidden) }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/local/bin/app")
    process.arguments = [cmd]
    try process.run()
    return "ok"
}
