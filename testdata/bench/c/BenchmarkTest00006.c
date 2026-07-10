#include <stdio.h>
#include <sqlite3.h>

void insert_user(const char *username, const char *email) {
    char query[512];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    sprintf(query, "INSERT INTO users (name, email) VALUES ('%s', '%s')", username, email);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
