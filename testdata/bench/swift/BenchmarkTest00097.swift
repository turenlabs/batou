import Vapor
import Foundation

class SafeData: NSObject, NSSecureCoding {
    static var supportsSecureCoding = true
    var name: String = ""
    func encode(with coder: NSCoder) { coder.encode(name, forKey: "name") }
    required init?(coder: NSCoder) {
        name = coder.decodeObject(of: NSString.self, forKey: "name") as String? ?? ""
    }
    override init() { super.init() }
}

func handler097(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
    unarchiver.requiresSecureCoding = true
    let obj = unarchiver.decodeObject(of: SafeData.self, forKey: NSKeyedArchiveRootObjectKey)
    return obj?.name ?? "nil"
}
