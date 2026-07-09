import Vapor
import Foundation

func handler046(_ req: Request) throws -> String {
    let tool = req.headers.first(name: "X-Tool") ?? "ls"
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/" + tool)
    try process.run()
    return "executed"
}
