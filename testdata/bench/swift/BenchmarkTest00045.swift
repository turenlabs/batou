import Vapor
import Foundation

func handler045(_ req: Request) throws -> String {
    let script = req.body.string ?? ""
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/bash")
    process.arguments = ["-c", script]
    try process.run()
    process.waitUntilExit()
    return "ran"
}
