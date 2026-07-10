import Vapor
import Foundation

func handler047(_ req: Request) throws -> String {
    let src = try req.parameters.require("src")
    let dst: String = try req.query.get(at: "dst")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/cp")
    process.arguments = [src, dst]
    try process.run()
    return "copied"
}
