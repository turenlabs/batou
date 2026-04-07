import Foundation
import Vapor

// SAFE: Path canonicalization + prefix check before file read
func handleFileDownload(req: Request) throws -> String {
    let filename = req.parameters.get("filename")!
    let baseDir = "/var/data"
    let resolvedPath = URL(fileURLWithPath: baseDir + "/" + filename)
        .standardizedFileURL.path
    guard resolvedPath.hasPrefix(baseDir) else {
        throw Abort(.forbidden)
    }
    let contents = try String(contentsOfFile: resolvedPath, encoding: .utf8)
    return contents
}

// SAFE: FileManager container URL provides sandboxed root
func readAppData() throws -> Data {
    let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.example")!
    let fileURL = container.appendingPathComponent("config.json")
    return try Data(contentsOf: fileURL)
}

// SAFE: XPath with escaped user input
func searchXML(query: String) throws -> [String] {
    let safeQuery = query.replacingOccurrences(of: "'", with: "&apos;")
    let xmlData = try Data(contentsOf: URL(fileURLWithPath: "/data/catalog.xml"))
    let doc = try XMLDocument(data: xmlData)
    let results = try doc.nodes(forXPath: "//item[name='\(safeQuery)']")
    return results.map { $0.stringValue ?? "" }
}

// SAFE: Hummingbird JSON response (not rendered as HTML)
func handleAPI(request: HBRequest) -> HBResponse {
    let jsonBody = "{\"status\": \"ok\"}"
    return HBResponse(status: .ok, body: .init(byteBuffer: ByteBuffer(string: jsonBody)))
}
