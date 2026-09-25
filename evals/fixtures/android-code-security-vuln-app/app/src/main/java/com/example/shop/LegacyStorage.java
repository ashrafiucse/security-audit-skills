package com.example.shop;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;

public class LegacyStorage {
    private final SharedPreferences prefs;

    public LegacyStorage(Context context) {
        prefs = context.getSharedPreferences("legacy_session", Context.MODE_PRIVATE);
    }

    public void persistToken(String accessToken) {
        prefs.edit().putString("legacy_token", accessToken).apply();
    }

    public void insertToken(SQLiteDatabase db, String accessToken) {
        db.execSQL("INSERT INTO session (token) VALUES ('" + accessToken + "')");
    }

    public void findCartByName(SQLiteDatabase db, String name) {
        db.execSQL("SELECT * FROM carts WHERE name = '" + name + "'");
    }
}
