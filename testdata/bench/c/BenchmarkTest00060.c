#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_log(const char *logname) {
    char input_path[512];
    char resolved[PATH_MAX];
    snprintf(input_path, sizeof(input_path), "/var/log/app/%s", logname);
    if (realpath(input_path, resolved) == NULL) return;
    if (strncmp(resolved, "/var/log/app/", 13) != 0) return;
    FILE *fp = fopen(resolved, "a");
    if (fp) fclose(fp);
}
