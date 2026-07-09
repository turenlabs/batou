import Vapor

func handler028(_ req: Request) throws -> Response {
    let title: String = try req.query.get(at: "title")
    let html = String(format: "<html><head><title>%@</title></head><body>Page</body></html>", title)
    return Response(status: .ok, body: .init(string: html))
}
