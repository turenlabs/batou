/* SAFE: strncat with explicit bounds checking.
 * Should NOT trigger GTSS-MEM-001.
 */

#include <stdio.h>
#include <string.h>

void build_greeting(const char *first_name, const char *last_name) {
    char greeting[128];
    size_t remaining;

    greeting[0] = '\0';

    /* Safe: using strncat with explicit remaining space calculation */
    strncat(greeting, "Hello, ", sizeof(greeting) - strlen(greeting) - 1);

    remaining = sizeof(greeting) - strlen(greeting) - 1;
    strncat(greeting, first_name, remaining);

    remaining = sizeof(greeting) - strlen(greeting) - 1;
    strncat(greeting, " ", remaining);

    remaining = sizeof(greeting) - strlen(greeting) - 1;
    strncat(greeting, last_name, remaining);

    remaining = sizeof(greeting) - strlen(greeting) - 1;
    strncat(greeting, "! Welcome.", remaining);

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
