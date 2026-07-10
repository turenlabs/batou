#include <cstdio>
#include <string>

void move_file(const std::string &src, const std::string &dst) {
    std::rename(src.c_str(), dst.c_str());
}
