/* VULN: Format string vulnerability - printf with user-controlled format string.
 * Should trigger GTSS-MEM-002 (Format String Vulnerability).
 */

#include <stdio.h>

void log_message(const char *user_input) {
    /* Vulnerable: user_input is used as the format string.
     * An attacker can supply "%x%x%x%x" to read stack memory,
     * or "%n" to write to arbitrary addresses.
     */
    printf(user_input);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }

    log_message(argv[1]);
    return 0;
}
