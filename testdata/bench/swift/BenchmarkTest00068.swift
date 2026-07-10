import Vapor
import Foundation

func handler068(_ req: Request) throws -> [String] {
    let dir: String = try req.query.get(at: "dir")
    let contents = try FileManager.default.contentsOfDirectory(atPath: dir)
    return contents
}
