import Vapor

func handler021(_ req: Request) throws -> Response {
    let name = try req.parameters.require("name")
    let html = "<html><body><h1>Hello, \(name)</h1></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
