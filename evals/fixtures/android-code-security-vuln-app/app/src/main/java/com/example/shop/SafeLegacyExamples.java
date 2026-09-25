package com.example.shop;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import okhttp3.CertificatePinner;

// SAFE counterparts, Java side. Same zero-raw-form contract as
// SafeExamples.kt.

public class SafeLegacyExamples {

    public static final String BASE_URL = "https://legacy.example-fake.com/v1";

    public static SharedPreferences securePrefs(Context context) {
        MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
        return EncryptedSharedPreferences.create(
                context, "legacy_secure_session", masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
    }

    public static void insertToken(SQLiteDatabase db, String token) {
        db.execSQL("INSERT INTO session (token) VALUES (?)", new Object[]{ token });
    }

    public static android.database.Cursor findCartByName(SQLiteDatabase db, String name) {
        return db.rawQuery("SELECT * FROM carts WHERE name = ?", new String[]{ name });
    }

    public static OkHttpClient pinnedClient() {
        CertificatePinner pinner = new CertificatePinner.Builder()
                .add("legacy.example-fake.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();
        return new OkHttpClient.Builder().certificatePinner(pinner).build();
    }
}
