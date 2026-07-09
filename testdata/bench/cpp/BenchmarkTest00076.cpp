#include <vector>
#include <cstring>

void process(const char *data, size_t len) {
    std::vector<char> buf(len);
    std::memcpy(buf.data(), data, len);
}
