import Vapor
import Foundation

func handler060(_ req: Request) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = ["status", "--porcelain"]
    try process.run()
    process.waitUntilExit()
    return "status checked"
}
