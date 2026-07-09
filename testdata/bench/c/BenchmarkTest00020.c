#include <sqlite3.h>

void find_by_range(const char *min_id, const char *max_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "SELECT * FROM items WHERE id BETWEEN ? AND ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, min_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, max_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
