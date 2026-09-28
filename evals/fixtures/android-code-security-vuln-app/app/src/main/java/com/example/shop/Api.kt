package com.example.shop

import android.util.Log
import okhttp3.OkHttpClient
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class Api {
    companion object {
        const val BASE_URL = "http://api.example-fake.com/v1"
        var authToken: String = ""
    }

    // Persona: user on hostile Wi-Fi. Trust manager accepts every chain —
    // MITM harvests the Authorization header on any network.
    private val trustAllCerts = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private val hostnameVerifier = HostnameVerifier { _, _ -> true }

    fun client(): OkHttpClient {
        val ssl = SSLContext.getInstance("TLS")
        ssl.init(null, arrayOf(trustAllCerts), null)
        return OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trustAllCerts)
            .hostnameVerifier(hostnameVerifier)
            .build()
    }

    fun authHeader(): String = "Bearer $authToken"

    // Release-build leakage: token goes to logcat (readable via adb, persisted
    // in bug reports and some vendor crash dumps).
    fun logSession() {
        Log.d("AUTH", "token: $authToken")
    }
}
