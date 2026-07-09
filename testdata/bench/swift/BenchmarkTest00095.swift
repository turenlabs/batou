import Vapor
import Foundation

struct AppConfig: Codable { var version: String; var debug: Bool }

func handler095(_ req: Request) throws -> String {
    let data = req.body.data ?? Data()
    let config = try PropertyListDecoder().decode(AppConfig.self, from: data)
    return config.version
}
