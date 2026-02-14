import Foundation
import WebKit

// VULNERABLE: WKWebView evaluateJavaScript with string interpolation
class ProfileController {
    var webView: WKWebView!

    func displayUserName(name: String) {
        webView.evaluateJavaScript("document.getElementById('username').innerText = '\(name)'")
    }

    func renderProfile(bio: String) {
        webView.loadHTMLString("<html><body><div>\(bio)</div></body></html>", baseURL: nil)
    }

    func executeScript(userScript: String) {
        let js = "eval(" + userScript + ")"
        webView.evaluateJavaScript(js)
    }
}

// VULNERABLE: UIWebView usage (deprecated)
class OldWebViewController: UIViewController {
    let oldWebView = UIWebView(frame: CGRect(x: 0, y: 0, width: 320, height: 480))

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(oldWebView)
    }
}
