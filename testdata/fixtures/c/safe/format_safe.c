/* SAFE: printf with explicit format specifier - user input is a data argument, not the format.
 * Should NOT trigger GTSS-MEM-002.
 */

#include <stdio.h>

void log_message(const char *user_input) {
    /* Safe: "%s" is a string literal format; user_input is a data argument */
    printf("%s\n", user_input);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }

    log_message(argv[1]);
    return 0;
}
