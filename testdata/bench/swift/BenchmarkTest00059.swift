import Vapor
import Foundation

func handler059(_ req: Request) throws -> String {
    let path: String = try req.query.get(at: "path")
    let fileManager = FileManager.default
    let exists = fileManager.fileExists(atPath: path)
    return exists ? "found" : "not found"
}
