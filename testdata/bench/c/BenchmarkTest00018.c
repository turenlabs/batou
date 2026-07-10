#include <sqlite3.h>

void get_admins(void) {
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, "SELECT * FROM users WHERE role = 'admin'", NULL, NULL, NULL);
    sqlite3_close(db);
}
