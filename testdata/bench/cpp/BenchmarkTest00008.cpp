#include <sstream>
#include <sqlite3.h>

void get_by_name(const std::string &name) {
    std::ostringstream oss;
    oss << "SELECT * FROM users WHERE name = '" << name << "'";
    std::string query = oss.str();
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
