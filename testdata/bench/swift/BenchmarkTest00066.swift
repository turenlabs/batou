import Vapor
import Foundation

func handler066(_ req: Request) throws -> String {
    let filename = try req.parameters.require("name")
    let content = req.body.string ?? ""
    let url = URL(fileURLWithPath: "/data/" + filename)
    try content.data(using: .utf8)?.write(to: url)
    return "written"
}
