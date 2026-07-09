#include <string.h>
#include <sqlite3.h>

void search(const char *term) {
    char query[1024];
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    strcpy(query, "SELECT * FROM products WHERE name = '");
    strcat(query, term);
    strcat(query, "'");
    sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_close(db);
}
