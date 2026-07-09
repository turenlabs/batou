#include <stdio.h>
#include <sqlite3.h>

void delete_record(const char *id) {
    char query[256];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sprintf(query, "DELETE FROM records WHERE id = %s", id);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
