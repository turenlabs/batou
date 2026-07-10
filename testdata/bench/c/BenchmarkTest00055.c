#include <stdio.h>
#include <libgen.h>

void safe_delete(const char *filename) {
    char *safe = basename((char *)filename);
    char path[512];
    snprintf(path, sizeof(path), "/uploads/%s", safe);
    remove(path);
}
