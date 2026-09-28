package com.example.shop

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.File

// Persona: end-user auth tokens. Device thief / rooted device / adb backup
// reads all three stores — none is Keychain/Keystore backed.
class Storage(context: Context) : SQLiteOpenHelper(context, "shop.db", null, 1) {
    private val prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE)

    fun persistTokens(accessToken: String, refreshToken: String) {
        prefs.edit().putString("access_token", accessToken).apply()
        prefs.edit().putString("refresh_token", refreshToken).apply()

        val tokenFile = File(context.filesDir, "tokens.txt")
        tokenFile.writeText("access=$accessToken\nrefresh=$refreshToken")
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE session (id INTEGER PRIMARY KEY, token TEXT)")
    }

    fun insertToken(db: SQLiteDatabase, accessToken: String) {
        db.execSQL("INSERT INTO session (token) VALUES ('$accessToken')")
    }

    // search() input arrives from the deeplink query in MainActivity — local
    // SQLi: the value is interpolated into the statement, not bound.
    fun findCartByName(db: SQLiteDatabase, name: String) {
        db.execSQL("SELECT * FROM carts WHERE name = '$name'")
    }
}
