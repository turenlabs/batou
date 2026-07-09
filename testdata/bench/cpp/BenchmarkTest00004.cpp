#include <string>
#include <sqlite3.h>

void update_name(const std::string &id, const std::string &name) {
    std::string query = "UPDATE users SET name = '" + name + "' WHERE id = " + id;
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
