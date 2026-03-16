// Source: CWE-89 - Android SQL Injection via rawQuery in Kotlin
// Expected: BATOU-KT
// OWASP: A03:2021 - Injection (SQL Injection)

import android.database.sqlite.SQLiteDatabase

fun searchUser(db: SQLiteDatabase, name: String) {
    val cursor = db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
    while (cursor.moveToNext()) {
        val email = cursor.getString(cursor.getColumnIndex("email"))
        println(email)
    }
    cursor.close()
}

fun deleteUser(db: SQLiteDatabase, id: String) {
    db.execSQL("DELETE FROM users WHERE id = ${id}")
}
