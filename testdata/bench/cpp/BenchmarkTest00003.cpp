#include <cstdio>
#include <sqlite3.h>

void delete_record(const char *id) {
    char query[256];
    sprintf(query, "DELETE FROM records WHERE id = %s", id);
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query, nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
