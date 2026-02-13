package com.example.safe

import android.database.sqlite.SQLiteDatabase
import androidx.room.Dao
import androidx.room.Query

class SafeUserRepository(private val db: SQLiteDatabase) {

    // Safe: parameterized rawQuery with selection args
    fun findUser(name: String): User? {
        val cursor = db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))
        return cursor.use { if (it.moveToFirst()) mapUser(it) else null }
    }

    // Safe: parameterized rawQuery with multiple args
    fun findUserByIdAndName(id: String, name: String): User? {
        val cursor = db.rawQuery(
            "SELECT * FROM users WHERE id = ? AND name = ?",
            arrayOf(id, name)
        )
        return cursor.use { if (it.moveToFirst()) mapUser(it) else null }
    }

    private fun mapUser(cursor: android.database.Cursor): User {
        return User(
            id = cursor.getInt(0),
            name = cursor.getString(1)
        )
    }
}

// Safe: Room DAO with parameterized queries
@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE name = :name")
    fun findByName(name: String): User

    @Query("SELECT * FROM users WHERE id = :id")
    fun findById(id: Int): User?
}

data class User(val id: Int, val name: String)
