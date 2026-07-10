import Vapor
import Foundation

func handler081(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let obj = NSKeyedUnarchiver.unarchiveObject(with: data)
    return "\(obj ?? "nil")"
}
