#include <string.h>

void copy_data(char *dst, const char *src, int user_len) {
    char buf[256];
    memcpy(buf, src, user_len);
}
