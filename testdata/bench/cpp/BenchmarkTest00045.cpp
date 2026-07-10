#include <cstdio>
#include <string>

void delete_file(const std::string &filename) {
    std::string path = "/uploads/" + filename;
    std::remove(path.c_str());
}
