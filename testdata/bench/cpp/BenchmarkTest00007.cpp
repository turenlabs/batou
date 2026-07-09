#include <string>
#include <sqlite3.h>

void find_user(const std::string &login) {
    std::string query = "SELECT * FROM users WHERE login = '" + login + "'";
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
