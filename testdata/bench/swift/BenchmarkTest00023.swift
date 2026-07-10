import Vapor
import WebKit

func handler023(_ req: Request) throws -> String {
    let code: String = try req.query.get(at: "code")
    let webView = WKWebView()
    webView.evaluateJavaScript("document.getElementById('result').innerHTML = '\(code)'", completionHandler: nil)
    return "executed"
}
