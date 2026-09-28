package com.example.shop

import android.webkit.JavascriptInterface
import android.webkit.WebView

// Persona: the page is THIRD-PARTY (URL arrives from a deeplink/intent), and
// the JS bridge exposes payment + file reads to whatever the page says.
class BillingWeb(private val webView: WebView) {
    fun loadPromo(url: String) {
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(Bridge(), "AppBridge")
        webView.loadUrl(url)
    }

    inner class Bridge {
        @JavascriptInterface
        fun pay(payload: String) {
            ChargeProcessor.submit(payload)
        }

        @JavascriptInterface
        fun readFile(path: String): String {
            return FileVault.read(path)
        }
    }
}

object ChargeProcessor {
    fun submit(payload: String) {}
}

object FileVault {
    fun read(path: String): String = ""
}
