#include <sqlite3.h>
#include <string>

void insert_user(const std::string &name, const std::string &email) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "INSERT INTO users (name, email) VALUES (?, ?)", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
