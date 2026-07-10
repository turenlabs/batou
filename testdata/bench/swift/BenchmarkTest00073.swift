import Vapor
import Foundation

func handler073(_ req: Request) throws -> Response {
    let data = FileManager.default.contents(atPath: "/etc/app/config.json")
    return Response(status: .ok, body: .init(data: data ?? Data()))
}
