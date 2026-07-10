import Vapor
import Foundation

func handler084(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let plist = try PropertyListSerialization.propertyList(from: data, format: nil)
    return "\(plist)"
}
