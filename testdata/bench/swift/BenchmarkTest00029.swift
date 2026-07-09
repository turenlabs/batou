import Vapor

func handler029(_ req: Request) throws -> Response {
    let firstName = try req.parameters.require("first")
    let lastName = try req.parameters.require("last")
    let html = "<table><tr><td>\(firstName)</td><td>\(lastName)</td></tr></table>"
    return Response(status: .ok, body: .init(string: html))
}
