#include <cstdio>
#include <sqlite3.h>

void lookup(const char *param) {
    char query[512];
    snprintf(query, sizeof(query), "SELECT id, name FROM items WHERE category = '%s'", param);
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query, nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
