import Vapor
import Foundation

func handler067(_ req: Request) throws -> String {
    let src = try req.parameters.require("src")
    let backupPath = "/backups/" + src
    try FileManager.default.copyItem(atPath: "/data/" + src, toPath: backupPath)
    return "backed up"
}
