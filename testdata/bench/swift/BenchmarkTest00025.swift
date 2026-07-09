import Vapor

func handler025(_ req: Request) throws -> Response {
    let username = req.cookies["username"]?.string ?? "guest"
    let html = "<html><body><span>Welcome back, \(username)!</span></body></html>"
    return Response(status: .ok, body: .init(string: html))
}
