import Vapor

enum Status: String, Content { case active, inactive, pending }

func handler094(_ req: Request) throws -> String {
    let status = try req.content.decode(Status.self)
    return "Status: \(status.rawValue)"
}
