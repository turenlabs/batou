package com.example.vulnerable

import android.database.sqlite.SQLiteDatabase

class UserRepository(private val db: SQLiteDatabase) {

    // Vulnerable: rawQuery with string concatenation
    fun findUser(name: String): User? {
        val cursor = db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
        return cursor.use { if (it.moveToFirst()) mapUser(it) else null }
    }

    // Vulnerable: rawQuery with string template
    fun findUserById(id: String): User? {
        val cursor = db.rawQuery("SELECT * FROM users WHERE id = ${id}", null)
        return cursor.use { if (it.moveToFirst()) mapUser(it) else null }
    }

    // Vulnerable: execSQL with string concatenation
    fun deleteUser(id: String) {
        db.execSQL("DELETE FROM users WHERE id = " + id)
    }

    // Vulnerable: execSQL with string template
    fun updateUser(id: String, name: String) {
        db.execSQL("UPDATE users SET name = '${name}' WHERE id = ${id}")
    }

    private fun mapUser(cursor: android.database.Cursor): User {
        return User(
            id = cursor.getInt(0),
            name = cursor.getString(1)
        )
    }
}

data class User(val id: Int, val name: String)
