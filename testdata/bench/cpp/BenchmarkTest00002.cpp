#include <string>
#include <sqlite3.h>

void search(const std::string &term) {
    std::string query = "SELECT * FROM products WHERE name = '";
    query += term;
    query += "'";
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
