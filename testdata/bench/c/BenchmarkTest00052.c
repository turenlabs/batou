#include <stdio.h>
#include <libgen.h>

void safe_read(const char *input) {
    char *name = basename((char *)input);
    char path[512];
    snprintf(path, sizeof(path), "/var/www/data/%s", name);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
