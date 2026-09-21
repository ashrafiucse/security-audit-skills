// Fixture: intentionally insecure WebView setup + hardcoded key. FAKE data only.
package com.example.vulnapp

class MainActivity : AppCompatActivity() {
    // SEC-06: hardcoded API key (trivial to extract via decompilation)
    private val PAYMENT_API_KEY = "pk_live_51FakeKeyForEvalFixtureXy9"

    fun onCreate() {
        val webView = findViewById<WebView>(R.id.web)
        // SEC-07: JS bridge + file access + attacker-influenced URL
        webView.settings.javaScriptEnabled = true
        webView.settings.allowFileAccess = true
        webView.addJavascriptInterface(WebBridge(), "AndroidBridge")
        webView.loadUrl(intent?.dataString ?: "http://update.example-fake.com/app")
    }
}
