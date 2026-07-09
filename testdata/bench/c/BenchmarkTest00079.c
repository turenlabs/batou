#include <stdlib.h>
#include <string.h>

void store(const char *data, size_t len) {
    if (len > 1024) return;
    char *buf = (char *)calloc(len + 1, 1);
    if (buf) {
        memcpy(buf, data, len);
        free(buf);
    }
}
