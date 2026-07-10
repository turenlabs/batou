#include <sqlite3.h>

void get_schema() {
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, "SELECT name FROM sqlite_master WHERE type='table'", nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
