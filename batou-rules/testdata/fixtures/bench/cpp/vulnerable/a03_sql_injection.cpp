// Source: CWE-89 - SQL Injection via sprintf in C++
// Expected: BATOU-MEM
// OWASP: A03:2021 - Injection (SQL Injection)

#include <cstdio>
#include <cstring>
#include <cstdlib>

void queryUser(const char* username) {
    char query[512];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", username);
    // execute(query);
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        queryUser(argv[1]);
    }
    return 0;
}
