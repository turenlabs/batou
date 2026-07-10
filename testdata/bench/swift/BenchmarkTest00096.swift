import Vapor
import Foundation

func handler096(_ req: Request) throws -> String {
    let json = """
    {"status": "ok", "version": "1.0"}
    """.data(using: .utf8)!
    let result = try JSONDecoder().decode([String: String].self, from: json)
    return result["status"] ?? "unknown"
}
