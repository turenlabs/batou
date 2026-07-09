#include <cstring>

void store(const char *data, size_t len) {
    if (len > 1024) return;
    char *buf = new char[len + 1];
    std::memcpy(buf, data, len);
    buf[len] = '\0';
    delete[] buf;
}
