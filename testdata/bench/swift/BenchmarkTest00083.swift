import Vapor
import Foundation

func handler083(_ req: Request) throws -> String {
    let path = try req.parameters.require("archive")
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let obj = NSKeyedUnarchiver.unarchiveObject(with: data)
    return "\(obj ?? "nil")"
}
