// VULN: SQL injection via ODBC with string concatenation.
// Should trigger detection for cpp.odbc.sqlexecdirect sink.

#include <sql.h>
#include <sqlext.h>
#include <string>
#include <cstdlib>

void search_products(SQLHSTMT stmt) {
    // User-controlled input from environment variable
    char *term = getenv("SEARCH_TERM");

    // Vulnerable: string concatenation in SQL query
    std::string query = "SELECT * FROM products WHERE name LIKE '%" + std::string(term) + "%'";
    SQLExecDirectA(stmt, (SQLCHAR*)query.c_str(), SQL_NTS);
}

void delete_user(SQLHSTMT stmt) {
    char *user_id = getenv("USER_ID");

    // Vulnerable: tainted input in DELETE query
    std::string query = "DELETE FROM users WHERE id = " + std::string(user_id);
    SQLExecDirectA(stmt, (SQLCHAR*)query.c_str(), SQL_NTS);
}
