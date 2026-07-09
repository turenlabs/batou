import Vapor

func handler100(_ req: Request) throws -> String {
    let name = try req.parameters.require("name")
    return "Hello, \(name)"
}
