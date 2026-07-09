#include <sqlite3.h>

void get_admins() {
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, "SELECT * FROM users WHERE role = 'admin'", nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
