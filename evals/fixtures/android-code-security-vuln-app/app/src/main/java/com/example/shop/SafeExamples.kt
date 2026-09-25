package com.example.shop

import android.app.PendingIntent
import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.webkit.WebView
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher

// SAFE counterparts for every android-code-security class, Kotlin side.
// Raw vulnerable forms have ZERO literal occurrences here (CI-enforced via
// MUST_NOT_MATCH rules in scripts/selftest_patterns.py).

object SafeStorage {
    fun securePrefs(context: android.content.Context): android.content.SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context, "secure_session", masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun insertToken(db: android.database.sqlite.SQLiteDatabase, token: String) {
        db.execSQL("INSERT INTO session (token) VALUES (?)", arrayOf(token))
    }

    fun findCartByName(db: android.database.sqlite.SQLiteDatabase, name: String) =
        db.rawQuery("SELECT * FROM carts WHERE name = ?", arrayOf(name))
}

object SafeNetwork {
    const val BASE_URL = "https://api.example-fake.com/v1"

    // Default trust + certificate pinning (OkHttp CertificatePinner)
    val pins = okhttp3.CertificatePinner.Builder()
        .add("api.example-fake.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build()

    fun client() = okhttp3.OkHttpClient.Builder()
        .certificatePinner(pins)
        .build()

    fun debugLog(msg: String) {
        if (BuildConfig.DEBUG) Log.d(SafeNetwork::class.java.simpleName, msg)
    }
}

object SafeWeb {
    fun loadHelp(webView: WebView) {
        webView.settings.javaScriptEnabled = false
        webView.loadUrl("https://help.example-fake.com/faq")
    }
}

object SafeIntents {
    private val routeAllowlist = mapOf(
        "item" to ItemDetailActivity::class.java,
        "promo" to PromoActivity::class.java
    )

    fun resolve(intent: Intent): Class<*>? {
        val segment = intent.data?.lastPathSegment ?: return null
        return routeAllowlist[segment]
    }

    fun notificationAction(context: android.content.Context, intent: Intent): PendingIntent {
        return PendingIntent.getActivity(
            context, 0, intent, PendingIntent.FLAG_IMMUTABLE
        )
    }
}

object SafeCrypto {
    fun keystoreKey(alias: String): javax.crypto.SecretKey {
        val generator = KeyStore.getInstance("AndroidKeyStore").let { ks ->
            ks.load(null)
            javax.crypto.KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        }
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return generator.generateKey()
    }

    fun encrypt(key: javax.crypto.SecretKey, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(plain)
    }

    fun fingerprint(payload: String): String =
        MessageDigest.getInstance("SHA-256").digest(payload.toByteArray())
            .joinToString("") { "%02x".format(it) }

    fun rng(): SecureRandom = SecureRandom()
}

class ItemDetailActivity
class PromoActivity
