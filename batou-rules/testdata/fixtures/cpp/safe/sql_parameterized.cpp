// SAFE: Parameterized SQL queries using ODBC, nanodbc, and Qt bindings.
// Should NOT trigger SQL injection detection.

#include <sql.h>
#include <sqlext.h>
#include <string>
#include <cstdlib>

// Safe ODBC: uses parameterized query with SQLBindParameter
void safe_odbc_query(SQLHSTMT stmt) {
    char *name = getenv("USERNAME");
    SQLPrepareA(stmt, (SQLCHAR*)"SELECT * FROM users WHERE name = ?", SQL_NTS);
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 255, 0, name, 0, NULL);
    SQLExecute(stmt);
}

// Safe SOCI: uses soci::use() for parameter binding
// soci::session sql("sqlite3", "app.db");
// std::string name = getenv("USERNAME");
// sql << "SELECT * FROM users WHERE name = :name", soci::use(name, "name");

// Safe Qt: uses bindValue for parameter binding
// QSqlQuery query;
// query.prepare("SELECT * FROM users WHERE name = :name");
// query.bindValue(":name", QString(getenv("USERNAME")));
// query.exec();
