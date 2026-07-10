#include <string.h>

void copy_safe_looking(const char *src) {
    char dst[64];
    strncpy(dst, src, strlen(src));
}
