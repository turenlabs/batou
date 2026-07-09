import Vapor
import Foundation

func handler089(_ req: Request) throws -> String {
    let headerVal = req.headers.first(name: "X-Session-State") ?? ""
    guard let data = Data(base64Encoded: headerVal) else { return "invalid" }
    let obj = NSKeyedUnarchiver.unarchiveObject(with: data)
    return "restored: \(obj ?? "nil")"
}
