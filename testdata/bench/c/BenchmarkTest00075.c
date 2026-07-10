#include <string.h>

void copy_data(const char *src, size_t src_len) {
    char buf[256];
    size_t copy_len = src_len < sizeof(buf) ? src_len : sizeof(buf);
    memcpy(buf, src, copy_len);
}
