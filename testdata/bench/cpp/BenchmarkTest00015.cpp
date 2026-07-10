#include <sqlite3.h>
#include <string>

void update_email(const std::string &id, const std::string &email) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "UPDATE users SET email = ? WHERE id = ?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
