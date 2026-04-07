import Foundation
import Vapor

// VULNERABLE: Path traversal via file read operations
func handleFileDownload(req: Request) throws -> String {
    let filename = req.parameters.get("filename")!

    // Path traversal: user controls the file path
    let contents = try String(contentsOfFile: "/var/data/" + filename, encoding: .utf8)
    return contents
}

func handleBinaryDownload(req: Request) throws -> Data {
    let path = req.query["path"] ?? ""

    // Path traversal: tainted path in Data read
    let url = URL(fileURLWithPath: "/uploads/" + path)
    let data = try Data(contentsOf: url)
    return data
}

func handleFileStream(req: Request) throws -> Response {
    let userPath = req.parameters.get("path")!

    // Path traversal: tainted path in FileHandle
    guard let handle = FileHandle(forReadingAtPath: "/documents/" + userPath) else {
        throw Abort(.notFound)
    }
    let data = handle.readDataToEndOfFile()
    return Response(status: .ok, body: .init(data: data))
}

func checkFileExists(req: Request) throws -> String {
    let name = req.parameters.get("name")!

    // Information disclosure: user can probe file existence
    if FileManager.default.fileExists(atPath: "/etc/" + name) {
        return "found"
    }
    return "not found"
}
