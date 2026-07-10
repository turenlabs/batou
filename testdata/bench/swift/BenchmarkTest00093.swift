import Vapor
import Foundation

func handler093(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let obj = try NSKeyedUnarchiver.unarchivedObject(ofClass: NSString.self, from: data)
    return obj as String? ?? "nil"
}
