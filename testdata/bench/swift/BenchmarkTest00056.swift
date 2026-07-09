import Vapor
import Foundation

func handler056(_ req: Request) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/local/bin/backup.sh")
    process.arguments = ["--daily"]
    try process.run()
    process.waitUntilExit()
    return "backed up"
}
