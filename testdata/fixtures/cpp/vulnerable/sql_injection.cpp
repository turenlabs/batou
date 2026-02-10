// VULN: SQL injection via string concatenation in query.
// Should trigger detection for cpp.sql.exec sink with tainted input.

#include <iostream>
#include <string>
#include <cstring>

// Simulated database interface (similar to sqlite3 API)
struct sqlite3;
typedef int (*sqlite3_callback)(void *, int, char **, char **);
extern int sqlite3_exec(sqlite3 *db, const char *sql,
                        sqlite3_callback callback, void *arg, char **errmsg);
extern int sqlite3_open(const char *filename, sqlite3 **db);
extern void sqlite3_close(sqlite3 *db);

void lookup_user(sqlite3 *db, const std::string &username) {
    // Vulnerable: user input concatenated into SQL query
    std::string query = "SELECT id, email FROM users WHERE username = '" + username + "'";

    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errmsg);
    if (rc != 0 && errmsg != nullptr) {
        std::cerr << "SQL error: " << errmsg << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <username>" << std::endl;
        return 1;
    }

    sqlite3 *db = nullptr;
    sqlite3_open("app.db", &db);
    lookup_user(db, argv[1]);
    sqlite3_close(db);
    return 0;
}
