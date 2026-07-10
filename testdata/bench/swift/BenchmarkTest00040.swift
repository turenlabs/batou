import Vapor

struct UserResponse: Content {
    var name: String
    var email: String
}
func handler040(_ req: Request) throws -> UserResponse {
    let name: String = try req.query.get(at: "name")
    return UserResponse(name: name, email: "test@example.com")
}
