import Vapor
import WebKit

func handler024(_ req: Request) throws -> String {
    let content = try req.content.decode(PageContent.self)
    let webView = WKWebView()
    webView.loadHTMLString("<html><body>\(content.body)</body></html>", baseURL: nil)
    return "loaded"
}
struct PageContent: Content { var body: String }
