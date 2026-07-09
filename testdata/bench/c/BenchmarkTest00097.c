#include <stdio.h>

void write_log(FILE *logfile, const char *entry) {
    fputs(entry, logfile);
    fputc('\n', logfile);
}
