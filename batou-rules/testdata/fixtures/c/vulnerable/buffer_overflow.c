/* VULN: Buffer overflow via strcpy from argv without bounds check.
 * Should trigger GTSS-MEM-001 (Banned Functions: strcpy).
 */

#include <stdio.h>
#include <string.h>

void process_name(const char *input) {
    char buffer[64];

    /* Vulnerable: no bounds checking, input may exceed 64 bytes */
    strcpy(buffer, input);

    printf("Processing: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }

    process_name(argv[1]);
    return 0;
}
