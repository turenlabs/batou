package com.example.safe

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

class SecureCredentialStorage(context: Context) {

    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    // Safe: using EncryptedSharedPreferences
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "secure_prefs",
        masterKeyAlias,
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    // Safe: sensitive data stored in encrypted preferences
    fun savePassword(password: String) {
        prefs.edit().putString("password", password).apply()
    }

    fun saveAuthToken(token: String) {
        prefs.edit().putString("auth_token", token).apply()
    }

    fun getPassword(): String? = prefs.getString("password", null)
    fun getAuthToken(): String? = prefs.getString("auth_token", null)
}
