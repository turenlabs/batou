#include <stdio.h>
#include <sqlite3.h>

void get_table(const char *table_name) {
    char query[256];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    snprintf(query, sizeof(query), "SELECT * FROM %s", table_name);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
