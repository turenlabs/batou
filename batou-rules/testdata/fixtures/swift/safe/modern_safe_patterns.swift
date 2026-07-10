import Foundation
import Vapor
import FluentKit
import CoreData
import WebKit

// SAFE: NSPredicate with parameterized arguments
func searchUsers(context: NSManagedObjectContext, name: String) -> [NSManagedObject] {
    let predicate = NSPredicate(format: "name == %@", name)
    let request = NSFetchRequest<NSManagedObject>(entityName: "User")
    request.predicate = predicate
    return try! context.fetch(request)
}

// SAFE: NSPredicate with argumentArray
func findByEmail(context: NSManagedObjectContext, email: String) -> [NSManagedObject] {
    let predicate = NSPredicate(format: "email == %@", argumentArray: [email])
    let request = NSFetchRequest<NSManagedObject>(entityName: "User")
    request.predicate = predicate
    return try! context.fetch(request)
}

// SAFE: Fluent ORM type-safe filter (parameterized)
func safeQuery(req: Request) async throws -> [User] {
    let search = req.query["search"] ?? ""
    return try await User.query(on: req.db)
        .filter(\.$name == search)
        .all()
}

// SAFE: Async URLSession with validated URL
func fetchProfile(req: Request) async throws -> Data {
    let userId = Int(req.query["id"] ?? "0") ?? 0
    let url = URL(string: "https://api.internal.example.com/users/\(userId)")!
    let (data, _) = try await URLSession.shared.data(from: url)
    return data
}

// SAFE: URL host validation before fetch
func safeFetch(urlString: String) async throws -> Data {
    guard let url = URL(string: urlString),
          url.scheme == "https",
          url.host == "api.example.com" else {
        throw Abort(.badRequest)
    }
    let (data, _) = try await URLSession.shared.data(from: url)
    return data
}

// SAFE: WKWebView with hardcoded URL
class SafeWebViewController {
    var webView: WKWebView!

    func loadDashboard() {
        let url = URL(string: "https://app.example.com/dashboard")!
        webView.load(URLRequest(url: url))
    }
}

// SAFE: directory listing via FileManager — no shell/Process, so no command
// injection surface at all (the secure Swift idiom; avoids spawning /bin/ls).
func listDirectory(path: String) -> [String] {
    guard path.wholeMatch(of: /^[a-zA-Z0-9_\/\-\.]+$/) != nil else { return [] }
    let fm = FileManager.default
    let contents = (try? fm.contentsOfDirectory(atPath: path)) ?? []
    return contents
}

// SAFE: URLComponents safe construction
func buildURL(query: String) -> URL? {
    var components = URLComponents(string: "https://api.example.com/search")!
    components.queryItems = [URLQueryItem(name: "q", value: query)]
    return components.url
}

// SAFE: Base64 encoding before logging
func logSafeData(sensitiveData: Data) {
    let encoded = sensitiveData.base64EncodedString()
    print(encoded)
}

// SAFE: Vapor response with Content-Type JSON (not HTML)
func safeResponse(req: Request) async throws -> Response {
    let data = try await fetchData()
    let response = Response(status: .ok, body: .init(data: data))
    response.headers.contentType = .json
    return response
}

func fetchData() async throws -> Data { return Data() }
