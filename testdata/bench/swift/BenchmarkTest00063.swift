import Vapor
import Foundation

func handler063(_ req: Request) throws -> Response {
    let logFile = try req.parameters.require("log")
    let content = try String(contentsOfFile: "/var/logs/" + logFile, encoding: .utf8)
    return Response(status: .ok, body: .init(string: content))
}
