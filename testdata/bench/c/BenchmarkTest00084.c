#include <stdio.h>

void format_output(const char *template_str) {
    char output[512];
    snprintf(output, sizeof(output), template_str);
}
