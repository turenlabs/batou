#include <sqlite3.h>
#include <stdio.h>

void search_pattern(const char *pattern) {
    char like_pattern[256];
    sqlite3 *db;
    sqlite3_stmt *stmt;
    snprintf(like_pattern, sizeof(like_pattern), "%%%s%%", pattern);
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "SELECT * FROM items WHERE name LIKE ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, like_pattern, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
