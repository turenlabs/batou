import Vapor

struct StrictInput: Content {
    var action: String
    var value: Int
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        action = try container.decode(String.self, forKey: .action)
        value = try container.decode(Int.self, forKey: .value)
    }
    enum CodingKeys: String, CodingKey { case action, value }
}

func handler098(_ req: Request) throws -> String {
    let input = try req.content.decode(StrictInput.self)
    return "\(input.action): \(input.value)"
}
