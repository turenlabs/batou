/* VULN: Command injection via system() with user-controlled string.
 * Should trigger detection for c.exec.system sink.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_diagnostic(const char *hostname) {
    char command[256];

    /* Vulnerable: user input concatenated into shell command.
     * An attacker can supply "8.8.8.8; rm -rf /" as hostname.
     */
    sprintf(command, "ping -c 3 %s", hostname);
    system(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        return 1;
    }

    run_diagnostic(argv[1]);
    return 0;
}
