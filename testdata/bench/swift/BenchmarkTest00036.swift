import Vapor

func handler036(_ req: Request) throws -> Response {
    let input: String = try req.query.get(at: "input")
    let safe = input.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
    let html = "<html><body><a href='/search?q=\(safe)'>Link</a></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
