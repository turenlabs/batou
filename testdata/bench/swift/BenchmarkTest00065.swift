import Vapor
import Foundation

func handler065(_ req: Request) throws -> String {
    let src: String = try req.query.get(at: "src")
    let dst: String = try req.query.get(at: "dst")
    try FileManager.default.moveItem(atPath: src, toPath: dst)
    return "moved"
}
