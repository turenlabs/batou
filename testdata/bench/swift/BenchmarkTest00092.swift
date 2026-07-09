import Vapor
import Foundation

struct Config: Codable { var host: String; var port: Int }

func handler092(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let config = try JSONDecoder().decode(Config.self, from: data)
    return "\(config.host):\(config.port)"
}
