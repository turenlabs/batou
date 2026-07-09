#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

void find_user(const char *input) {
    char buf[256];
    char query[512];
    sqlite3 *db;
    strcpy(buf, input);
    sqlite3_open("app.db", &db);
    sprintf(query, "SELECT * FROM users WHERE login = '%s'", buf);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
