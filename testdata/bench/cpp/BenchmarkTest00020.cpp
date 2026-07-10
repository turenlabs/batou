#include <sqlite3.h>
#include <cstdlib>

void get_user(const char *id_str) {
    int id = std::atoi(id_str);
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
