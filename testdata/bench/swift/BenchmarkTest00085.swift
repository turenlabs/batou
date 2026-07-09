import Vapor
import Foundation

class UnsafeData: NSObject, NSCoding {
    var command: String = ""
    func encode(with coder: NSCoder) { coder.encode(command, forKey: "cmd") }
    required init?(coder: NSCoder) {
        command = coder.decodeObject(forKey: "cmd") as? String ?? ""
    }
}

func handler085(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let obj = NSKeyedUnarchiver.unarchiveObject(with: data) as? UnsafeData
    return obj?.command ?? "none"
}
