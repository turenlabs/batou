import Vapor

func handler034(_ req: Request) throws -> EventLoopFuture<Response> {
    struct SearchResult: Content { var query: String; var count: Int }
    let q: String = try req.query.get(at: "q")
    let result = SearchResult(query: q, count: 0)
    return result.encodeResponse(for: req)
}
