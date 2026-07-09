#include <sqlite3.h>
#include <string>
#include <cstdio>

void search_pattern(const std::string &pattern) {
    char like_pat[256];
    snprintf(like_pat, sizeof(like_pat), "%%%s%%", pattern.c_str());
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "SELECT * FROM items WHERE name LIKE ?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, like_pat, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
