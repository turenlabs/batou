#include <stdio.h>

void write_log(FILE *logfile, const char *entry) {
    fprintf(logfile, entry);
}
