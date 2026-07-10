#include <stdio.h>
#include <sqlite3.h>

void handle_request(const char *user_input) {
    char query[512];
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    snprintf(query, sizeof(query), "SELECT name FROM accounts WHERE user = '%s'", user_input);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
