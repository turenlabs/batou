import Vapor
import Foundation

func handler041(_ req: Request) throws -> String {
    let filename = try req.parameters.require("file")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/cat")
    process.arguments = [filename]
    try process.run()
    process.waitUntilExit()
    return "done"
}
