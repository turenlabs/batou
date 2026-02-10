/* SAFE: Bounds-checked string copy using snprintf.
 * Should NOT trigger GTSS-MEM-001.
 */

#include <stdio.h>
#include <string.h>

void process_name(const char *input) {
    char buffer[64];

    /* Safe: snprintf limits output to buffer size */
    snprintf(buffer, sizeof(buffer), "%s", input);

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
