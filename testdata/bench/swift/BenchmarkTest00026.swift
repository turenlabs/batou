import Vapor

func handler026(_ req: Request) throws -> Response {
    let lang = req.headers.first(name: "Accept-Language") ?? "en"
    let html = "<html lang='" + lang + "'><body>Content</body></html>"
    return Response(status: .ok, body: .init(string: html))
}
