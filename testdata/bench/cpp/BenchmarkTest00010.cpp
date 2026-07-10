#include <string>
#include <sqlite3.h>

void search_like(const std::string &pattern) {
    std::string query = "SELECT * FROM items WHERE name LIKE '%" + pattern + "%'";
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
