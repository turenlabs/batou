import Vapor
import Foundation

func handler043(_ req: Request) throws -> String {
    let cmd = try req.content.decode(CommandInput.self).command
    let task = Process()
    task.launchPath = "/bin/sh"
    task.arguments = ["-c", cmd]
    task.launch()
    return "executed"
}
struct CommandInput: Content { var command: String }
