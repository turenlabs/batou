import Vapor
import Foundation

func handler069(_ req: Request) throws -> String {
    let target = try req.parameters.require("target")
    let link = try req.parameters.require("link")
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
    return "linked"
}
