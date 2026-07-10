#include <cstring>

void build_path(const char *dir, const char *file) {
    char path[64];
    strcpy(path, dir);
    strcat(path, "/");
    strcat(path, file);
}
