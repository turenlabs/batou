#include <cstring>

void copy_looks_safe(const char *src) {
    char dst[64];
    strncpy(dst, src, strlen(src));
}
