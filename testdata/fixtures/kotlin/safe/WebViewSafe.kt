package com.example.safe

import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

class SafeWebViewActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.webViewClient = WebViewClient()

        // Safe: loading a static trusted URL
        webView.loadUrl("https://example.com/app")
    }

    // Safe: using evaluateJavascript with JSON-encoded data
    fun updateName(userInput: String) {
        val encoded = JSONObject.quote(userInput)
        webView.evaluateJavascript("updateName($encoded)", null)
    }

    // Safe: using WebMessagePort for communication
    fun sendMessage(message: String) {
        // Using postWebMessage for safe cross-origin communication
        webView.postVisualStateCallback(0, object : WebView.VisualStateCallback() {
            override fun onComplete(requestId: Long) {}
        })
    }
}
