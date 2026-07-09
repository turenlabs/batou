#include <stdlib.h>
#include <sqlite3.h>

void get_user(const char *id_str) {
    int id = atoi(id_str);
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open(":memory:", &db);
    sqlite3_prepare_v2(db, "SELECT name FROM users WHERE id = ?", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
