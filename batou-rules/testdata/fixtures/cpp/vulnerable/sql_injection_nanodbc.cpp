// VULN: SQL injection via nanodbc with string concatenation.
// Should trigger detection for cpp.nanodbc.execute and cpp.nanodbc.just_execute sinks.

#include <nanodbc/nanodbc.h>
#include <string>
#include <cstdlib>

void find_items(nanodbc::connection& conn) {
    char *search = getenv("SEARCH");

    // Vulnerable: tainted input concatenated into SQL
    std::string sql = "SELECT * FROM items WHERE name = '" + std::string(search) + "'";
    nanodbc::execute(conn, sql);
}

void remove_record(nanodbc::connection& conn) {
    char *id = getenv("RECORD_ID");

    // Vulnerable: tainted input in DELETE
    std::string sql = "DELETE FROM records WHERE id = " + std::string(id);
    nanodbc::just_execute(conn, sql);
}
