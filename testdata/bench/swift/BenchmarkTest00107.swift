import Vapor
import UIKit

func handler107(_ req: Request) throws -> String {
    let link: String = try req.query.get(at: "link")
    if let url = URL(string: link) {
        UIApplication.shared.open(url)
    }
    return "opened"
}
