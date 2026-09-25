package com.example.shop;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;

// Java legacy twin: the same classes, pre-Kotlin migration. Same bugs.
public class LegacyApi {
    public static final String BASE_URL = "http://legacy.example-fake.com/v1";

    private final TrustManager[] trustAllCerts = new TrustManager[]{
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }
    };

    private final HostnameVerifier hostnameVerifier = new HostnameVerifier() {
        public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
            return true;
        }
    };

    public OkHttpClient buildClient() throws Exception {
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, trustAllCerts, null);
        return new OkHttpClient.Builder()
                .sslSocketFactory(ssl.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                .hostnameVerifier(hostnameVerifier)
                .build();
    }

    public String tokenHeader() {
        return "Bearer " + StorageHolder.authToken;
    }

    public void logSession() {
        Log.d("AUTH", "legacy session ok");
    }
}
