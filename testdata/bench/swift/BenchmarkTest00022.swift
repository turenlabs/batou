import Vapor

func handler022(_ req: Request) throws -> Response {
    let search: String = try req.query.get(at: "q")
    let body = "<div class='results'><p>Results for: \(search)</p></div>"
    var headers = HTTPHeaders()
    headers.add(name: .contentType, value: "text/html")
    return Response(status: .ok, headers: headers, body: .init(string: body))
}
