package com.example.shop

import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Persona: ANY OTHER APP can send intents/deeplinks to exported
        // components. External string goes straight into a component launch.
        val target = intent.getStringExtra("screen")
        if (target != null) {
            val open = Intent(this, Class.forName("com.example.shop.$target"))
            startActivity(open)
        }

        // Notification action: flags = 0 means MUTABLE — a pinned notification
        // intent can be hijacked/rewritten by another app on some versions.
        val notify = Intent(this, OrderSyncService::class.java)
        val pi = PendingIntent.getActivity(this, 0, notify, 0)
        showNotification(pi)
    }

    private fun showNotification(pi: PendingIntent) {
        Log.d("NAV", "notification armed")
    }
}
