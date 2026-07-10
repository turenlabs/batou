import Vapor

func handler054(_ req: Request) throws -> String {
    let input = try req.parameters.require("name")
    return "Hello, \(input)"
}
