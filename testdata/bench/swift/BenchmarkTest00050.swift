import Vapor
import Foundation

func handler050(_ req: Request) throws -> String {
    struct Config: Content { var path: String; var args: [String] }
    let config = try req.content.decode(Config.self)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: config.path)
    process.arguments = config.args
    try process.run()
    return "ran"
}
