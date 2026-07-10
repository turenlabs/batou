import Vapor

func handler037(_ req: Request) throws -> Response {
    let html = "<html><body><h1>Welcome to our site</h1><p>Static content</p></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
