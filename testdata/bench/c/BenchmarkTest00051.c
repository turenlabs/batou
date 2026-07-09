#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_file(const char *filename) {
    char resolved[PATH_MAX];
    const char *base = "/var/www/data/";
    if (realpath(filename, resolved) == NULL) return;
    if (strncmp(resolved, base, strlen(base)) != 0) return;
    FILE *fp = fopen(resolved, "r");
    if (fp) fclose(fp);
}
