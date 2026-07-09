import Vapor
import Foundation

enum Action: String, Content { case start, stop, restart }
func handler058(_ req: Request) throws -> String {
    let action = try req.content.decode(Action.self)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/local/bin/service")
    process.arguments = [action.rawValue]
    try process.run()
    return "done"
}
