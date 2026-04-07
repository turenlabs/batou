package com.example.vulnerable

import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class WebViewActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this)
        webView.settings.javaScriptEnabled = true

        // Vulnerable: addJavascriptInterface exposes Kotlin objects to JavaScript
        webView.addJavascriptInterface(JsBridge(), "Android")
        webView.loadUrl("https://example.com")
    }

    // Vulnerable: loadUrl with javascript: protocol and string concatenation
    fun updateName(userInput: String) {
        webView.loadUrl("javascript:updateName('" + userInput + "')")
    }

    // Vulnerable: loadUrl with javascript: protocol and string template
    fun updateEmail(userInput: String) {
        webView.loadUrl("javascript:updateEmail('${userInput}')")
    }

    // Vulnerable: evaluateJavascript with string concatenation
    fun setField(fieldName: String, value: String) {
        webView.evaluateJavascript("document.getElementById('name').value = '" + value + "'", null)
    }

    inner class JsBridge {
        @JavascriptInterface
        fun getToken(): String {
            return getSharedPreferences("auth", MODE_PRIVATE).getString("token", "") ?: ""
        }
    }
}
