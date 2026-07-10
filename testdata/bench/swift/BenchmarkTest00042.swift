import Vapor
import Foundation

func handler042(_ req: Request) throws -> String {
    let host: String = try req.query.get(at: "host")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/bash")
    process.arguments = ["-c", "ping -c 1 \(host)"]
    try process.run()
    return "pinged"
}
