import Vapor

struct UserInput: Content { var name: String; var age: Int }

func handler091(_ req: Request) throws -> String {
    let input = try req.content.decode(UserInput.self)
    return "Hello, \(input.name)"
}
