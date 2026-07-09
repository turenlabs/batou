#include <stdio.h>
#include <sqlite3.h>

void update_name(const char *id, const char *name) {
    char query[512];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sprintf(query, "UPDATE users SET name = '%s' WHERE id = %s", name, id);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
