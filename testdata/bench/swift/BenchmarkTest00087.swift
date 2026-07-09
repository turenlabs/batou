import Vapor
import Foundation

func handler087(_ req: Request) throws -> String {
    let b64 = req.cookies["state"]?.string ?? ""
    guard let data = Data(base64Encoded: b64) else { throw Abort(.badRequest) }
    let state = NSKeyedUnarchiver.unarchiveObject(with: data)
    return "\(state ?? "nil")"
}
