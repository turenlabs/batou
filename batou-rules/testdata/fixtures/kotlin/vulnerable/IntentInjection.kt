package com.example.vulnerable

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class DataShareActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val userMessage = intent.getStringExtra("message")

        // Vulnerable: implicit intent with user data via sendBroadcast
        val broadcastIntent = Intent("com.example.DATA_RECEIVED")
        broadcastIntent.putExtra("data", userMessage)
        sendBroadcast(broadcastIntent)
    }

    // Vulnerable: implicit intent with user-controlled data
    fun shareUserData() {
        val userData = intent.getStringExtra("user_data")
        val shareIntent = Intent("com.example.SHARE_DATA")
        shareIntent.putExtra("content", userData)
        startActivity(shareIntent)
    }
}
