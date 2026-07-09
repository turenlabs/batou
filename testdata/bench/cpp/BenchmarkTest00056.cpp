#include <cstdio>
#include <cstring>
#include <string>

void safe_open(const std::string &filename) {
    if (filename.find("..") != std::string::npos) return;
    std::string path = "/data/" + filename;
    FILE *fp = fopen(path.c_str(), "r");
    if (fp) fclose(fp);
}
