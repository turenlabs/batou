import Vapor
import Foundation

func handler090(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let json = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves) as? NSDictionary
    let className = json?["type"] as? String ?? ""
    let cls = NSClassFromString(className)
    return "type: \(cls ?? NSObject.self)"
}
