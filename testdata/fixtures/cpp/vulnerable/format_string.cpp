// VULN: Format string vulnerability - printf with user-controlled format argument.
// Should trigger GTSS-MEM-002 (Format String Vulnerability) for C++.

#include <cstdio>
#include <iostream>

void log_user_message(const char *user_input) {
    // Vulnerable: user_input is used as the format string
    printf(user_input);
    printf("\n");

    // Also vulnerable: fprintf with variable format
    fprintf(stderr, user_input);
    fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <message>" << std::endl;
        return 1;
    }

    // User can supply "%p%p%p%n" to read/write memory
    log_user_message(argv[1]);
    return 0;
}
