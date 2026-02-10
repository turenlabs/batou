/* VULN: strcat without buffer size check - unbounded concatenation.
 * Should trigger GTSS-MEM-001 (Banned Functions: strcat).
 */

#include <stdio.h>
#include <string.h>

void build_greeting(const char *first_name, const char *last_name) {
    char greeting[64];

    strcpy(greeting, "Hello, ");
    /* Vulnerable: strcat does not check if the result fits in the buffer.
     * If first_name + last_name exceed ~55 bytes, this overflows.
     */
    strcat(greeting, first_name);
    strcat(greeting, " ");
    strcat(greeting, last_name);
    strcat(greeting, "! Welcome.");

    printf("%s\n", greeting);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <first> <last>\n", argv[0]);
        return 1;
    }

    build_greeting(argv[1], argv[2]);
    return 0;
}
