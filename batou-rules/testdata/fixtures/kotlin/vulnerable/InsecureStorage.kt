package com.example.vulnerable

import android.content.Context
import android.content.SharedPreferences

class CredentialStorage(private val context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE)

    // Vulnerable: storing password in unencrypted SharedPreferences
    fun savePassword(password: String) {
        prefs.edit().putString("password", password).apply()
    }

    // Vulnerable: storing API key in unencrypted SharedPreferences
    fun saveApiKey(apiKey: String) {
        prefs.edit().putString("api_key", apiKey).apply()
    }

    // Vulnerable: storing auth token in unencrypted SharedPreferences
    fun saveAuthToken(token: String) {
        prefs.edit().putString("auth_token", token).apply()
    }

    // Vulnerable: storing secret in unencrypted SharedPreferences
    fun saveSecret(secret: String) {
        prefs.edit().putString("secret", secret).apply()
    }

    fun getPassword(): String? = prefs.getString("password", null)
    fun getApiKey(): String? = prefs.getString("api_key", null)
}
