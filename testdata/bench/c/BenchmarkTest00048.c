#include <stdio.h>

void redirect_output(const char *logfile) {
    freopen(logfile, "a", stdout);
    printf("Logging started\n");
}
