#include <sqlite3.h>

void count_users(void) {
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db, "SELECT COUNT(*) FROM users", NULL, NULL, NULL);
    sqlite3_close(db);
}
