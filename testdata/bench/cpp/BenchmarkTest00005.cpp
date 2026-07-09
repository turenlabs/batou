#include <string>
#include <sqlite3.h>

void insert_user(const std::string &username, const std::string &email) {
    std::string query = "INSERT INTO users (name, email) VALUES ('" + username + "', '" + email + "')";
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
}
