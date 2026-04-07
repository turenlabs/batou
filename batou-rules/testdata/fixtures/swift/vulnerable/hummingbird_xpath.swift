import Foundation
import Hummingbird

// VULNERABLE: Hummingbird response with tainted body (XSS)
func handleProfile(request: HBRequest) -> HBResponse {
    let name = request.parameters.get("name") ?? ""
    let body = "<html><body><h1>Hello, \(name)</h1></body></html>"
    return HBResponse(status: .ok, body: .init(byteBuffer: ByteBuffer(string: body)))
}

// VULNERABLE: Hummingbird open redirect
func handleRedirect(request: HBRequest) -> HBResponse {
    let target = request.uri.queryString ?? "/"
    return HBResponse(status: .movedPermanently, headers: ["Location": target])
}

// VULNERABLE: XPath injection via user input
func searchXML(request: HBRequest) throws -> String {
    let query = request.parameters.get("query") ?? ""
    let xmlData = try Data(contentsOf: URL(fileURLWithPath: "/data/catalog.xml"))
    let doc = try XMLDocument(data: xmlData)

    // XPath injection: user controls the XPath expression
    let results = try doc.nodes(forXPath: "//item[name='\(query)']")
    return results.map { $0.stringValue ?? "" }.joined(separator: "\n")
}

// VULNERABLE: URLSession upload to tainted URL (SSRF/exfiltration)
func exfilData(request: HBRequest) async throws -> String {
    let webhookURL = request.parameters.get("callback") ?? ""
    let payload = "sensitive data".data(using: .utf8)!
    let url = URL(string: webhookURL)!
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = "POST"
    let (_, response) = try await URLSession.shared.upload(for: urlRequest, from: payload)
    return "sent"
}
