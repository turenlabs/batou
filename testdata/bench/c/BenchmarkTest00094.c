#include <stdio.h>

void format_output(const char *text) {
    char output[512];
    snprintf(output, sizeof(output), "Message: %s", text);
}
