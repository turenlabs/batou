import Vapor
import Foundation

func handler044(_ req: Request) throws -> String {
    let binary = try req.parameters.require("binary")
    let process = Process()
    process.launchPath = binary
    process.arguments = ["--version"]
    try process.run()
    return "launched"
}
