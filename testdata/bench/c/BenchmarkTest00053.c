#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void serve_file(const char *name) {
    char input_path[512];
    char resolved[PATH_MAX];
    snprintf(input_path, sizeof(input_path), "/var/www/static/%s", name);
    if (realpath(input_path, resolved) == NULL) return;
    if (strncmp(resolved, "/var/www/static/", 16) != 0) return;
    FILE *fp = fopen(resolved, "r");
    if (fp) fclose(fp);
}
