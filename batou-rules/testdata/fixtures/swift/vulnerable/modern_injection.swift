import Foundation
import Vapor
import FluentKit
import CoreData
import WebKit
import SafariServices

// VULNERABLE: Core Data NSPredicate injection via string interpolation
func searchUsers(context: NSManagedObjectContext, name: String) -> [NSManagedObject] {
    let predicate = NSPredicate(format: "name == '\(name)'")
    let request = NSFetchRequest<NSManagedObject>(entityName: "User")
    request.predicate = predicate
    return try! context.fetch(request)
}

// VULNERABLE: NSPredicate with concatenation
func findByEmail(context: NSManagedObjectContext, email: String) -> [NSManagedObject] {
    let predicate = NSPredicate(format: "email == '" + email + "'")
    let request = NSFetchRequest<NSManagedObject>(entityName: "User")
    request.predicate = predicate
    return try! context.fetch(request)
}

// VULNERABLE: NSExpression with tainted format
func evaluateExpression(userInput: String) -> Any? {
    let expr = NSExpression(format: userInput)
    return expr.expressionValue(with: nil, context: nil)
}

// VULNERABLE: Fluent ORM raw SQL with interpolation
func rawQuery(req: Request) async throws -> [Row] {
    let search = req.query["search"] ?? ""
    return try await req.db.raw("SELECT * FROM users WHERE name = '\(search)'").all()
}

// VULNERABLE: Fluent raw with SQLQueryString
func rawDelete(db: Database, userId: String) async throws {
    try await db.raw("DELETE FROM sessions WHERE user_id = \(userId)").run()
}

// VULNERABLE: Async URLSession SSRF
func fetchProfile(req: Request) async throws -> Data {
    let url = req.query["url"] ?? ""
    let targetURL = URL(string: url)!
    let (data, _) = try await URLSession.shared.data(from: targetURL)
    return data
}

// VULNERABLE: Async URLSession download SSRF
func downloadFile(req: Request) async throws -> URL {
    let url = req.query["file_url"] ?? ""
    let targetURL = URL(string: url)!
    let (localURL, _) = try await URLSession.shared.download(from: targetURL)
    return localURL
}

// VULNERABLE: WKWebView loading tainted URL
class UnsafeWebViewController {
    var webView: WKWebView!

    func loadUserURL(urlString: String) {
        let url = URL(string: urlString)!
        webView.load(URLRequest(url: url))
    }
}

// VULNERABLE: Process.run() with tainted arguments
func executeCommand(command: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", command]
    process.run()
}

// VULNERABLE: Realm filter with string predicate
func searchItems(realm: Any, query: String) {
    // Simulated Realm query with tainted predicate
    let predicate = NSPredicate(format: "title CONTAINS '\(query)'")
    _ = predicate
}

// VULNERABLE: SFSafariViewController with tainted URL
func openInSafari(viewController: UIViewController, urlString: String) {
    let url = URL(string: urlString)!
    let safari = SFSafariViewController(url: url)
    viewController.present(safari, animated: true)
}

// VULNERABLE: Vapor WebSocket echo without sanitization
func setupWebSocket(app: Application) {
    app.webSocket("echo") { req, ws in
        ws.onText { ws, text in
            ws.send(text)
        }
    }
}

// VULNERABLE: Hummingbird request body used in SQL
func hummingbirdHandler(request: HBRequest, db: OpaquePointer?) {
    let path = request.uri.path
    let query = "SELECT * FROM pages WHERE path = '\(path)'"
    sqlite3_exec(db, query, nil, nil, nil)
}
