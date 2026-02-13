package com.example.safe

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class SafeDataActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val userMessage = intent.getStringExtra("message")

        // Safe: using LocalBroadcastManager for app-internal communication
        val broadcastIntent = Intent("com.example.DATA_RECEIVED")
        broadcastIntent.putExtra("data", userMessage)
        LocalBroadcastManager.getInstance(this).sendBroadcast(broadcastIntent)
    }

    // Safe: explicit intent with specific target
    fun openDetail(context: Context) {
        val intent = Intent(context, DetailActivity::class.java)
        intent.putExtra("id", 42)
        startActivity(intent)
    }
}

class DetailActivity : AppCompatActivity()
