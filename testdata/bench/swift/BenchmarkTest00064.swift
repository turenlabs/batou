import Vapor
import Foundation

func handler064(_ req: Request) throws -> String {
    struct Upload: Content { var filename: String; var data: Data }
    let upload = try req.content.decode(Upload.self)
    let path = "/uploads/" + upload.filename
    FileManager.default.createFile(atPath: path, contents: upload.data)
    return "uploaded"
}
