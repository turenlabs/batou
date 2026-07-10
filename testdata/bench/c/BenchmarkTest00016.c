#include <sqlite3.h>

void delete_user(const char *id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "DELETE FROM users WHERE id = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
