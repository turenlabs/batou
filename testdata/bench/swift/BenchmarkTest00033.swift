import Vapor

func handler033(_ req: Request) throws -> Response {
    let search: String = try req.query.get(at: "q")
    let result = ["query": search, "results": []]
    return try Response(status: .ok, body: .init(data: JSONEncoder().encode(result)))
}
