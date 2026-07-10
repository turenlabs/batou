// SAFE: non-handler helper functions with std::string / char* params.
//
// These functions are NOT handler-shaped (run_query, lookup_user, format_row),
// so their parameters are NOT auto-seeded as taint sources. They receive
// constant or parameterized values from their callers (modeled precisely by
// the interprocedural call graph), so no intraprocedural taint flow should be
// reported here.

#include <string>
#include <cstdio>
#include <cstdlib>

struct DB {
    void query(const std::string &sql);
};

// Non-handler helper: parameterized query, value bound — NOT a flow.
void run_query(DB *db, const std::string &q) {
    // Parameterized: the SQL text is constant, q is bound separately.
    db->query("SELECT id FROM users WHERE name = ?");
    (void)q;
}

// Non-handler helper: receives a constant from its caller.
void lookup_user(const std::string &username) {
    std::string full = "SELECT 1";
    (void)username;
    (void)full;
}

// Non-handler helper formatting a constant.
void format_row(char *buf) {
    (void)buf;
}
