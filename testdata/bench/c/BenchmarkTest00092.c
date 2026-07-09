#include <stdio.h>

void log_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}
