#include <algorithm>
#include <cstring>

void copy_data(const char *src, size_t src_len) {
    char buf[256];
    size_t copy_len = std::min(src_len, sizeof(buf));
    std::copy(src, src + copy_len, buf);
}
