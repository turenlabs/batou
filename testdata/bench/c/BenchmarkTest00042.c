#include <stdio.h>

void serve_file(const char *name) {
    char path[512];
    sprintf(path, "/var/www/data/%s", name);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
