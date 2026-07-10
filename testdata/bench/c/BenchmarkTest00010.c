#include <stdio.h>
#include <sqlite3.h>

void search_like(const char *pattern) {
    char query[512];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sprintf(query, "SELECT * FROM items WHERE name LIKE '%%%s%%'", pattern);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
