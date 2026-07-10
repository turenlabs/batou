#include <stdio.h>
#include <string.h>

void safe_open(const char *filename) {
    if (strstr(filename, "..") != NULL) return;
    char path[512];
    snprintf(path, sizeof(path), "/data/%s", filename);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
