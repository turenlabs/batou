#include <string>
#include <sqlite3.h>

void handle_request(const std::string &user_input) {
    std::string query = "SELECT * FROM users WHERE id = " + user_input;
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
