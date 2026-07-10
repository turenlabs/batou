#include <string>
#include <sqlite3.h>

void get_table(const std::string &table_name) {
    std::string query = "SELECT * FROM " + table_name;
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
