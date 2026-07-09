import Vapor

func handler038(_ req: Request) throws -> String {
    let name = try req.parameters.require("name")
    return "Hello, \(name)"
}
