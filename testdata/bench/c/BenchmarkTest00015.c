#include <sqlite3.h>

void insert_user(const char *name, const char *email) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "INSERT INTO users (name, email) VALUES (?, ?)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, email, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
