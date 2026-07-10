#include <stdio.h>
#include <sqlite3.h>

void lookup(const char *param) {
    char query[512];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    snprintf(query, sizeof(query), "SELECT id, name FROM items WHERE category = '%s'", param);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
