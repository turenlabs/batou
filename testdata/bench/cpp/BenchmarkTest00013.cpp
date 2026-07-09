#include <sqlite3.h>

void count_users() {
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db, "SELECT COUNT(*) FROM users", nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
