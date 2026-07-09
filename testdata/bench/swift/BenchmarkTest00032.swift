import Vapor

func handler032(_ req: Request) throws -> Response {
    let name = try req.parameters.require("name")
    let escaped = name.replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "&", with: "&amp;")
    let html = "<html><body><h1>Hello, \(escaped)</h1></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
