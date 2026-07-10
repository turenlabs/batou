import Vapor
import Foundation

func handler051(_ req: Request) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/uptime")
    try process.run()
    process.waitUntilExit()
    return "ok"
}
