import Vapor

func handler106(_ req: Request) throws -> Response {
    let next: String = try req.query.get(at: "next")
    var response = Response(status: .movedPermanently)
    response.headers.replaceOrAdd(name: .location, value: next)
    return response
}
