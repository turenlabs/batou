#include <stdio.h>

void delete_file(const char *filename) {
    char path[512];
    sprintf(path, "/uploads/%s", filename);
    remove(path);
}
