import Vapor

func handler110(_ req: Request) throws -> Response {
    struct LoginResult: Content { var token: String; var returnTo: String }
    let result = try req.content.decode(LoginResult.self)
    return req.redirect(to: result.returnTo)
}
