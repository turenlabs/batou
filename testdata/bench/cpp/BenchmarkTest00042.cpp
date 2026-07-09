#include <cstdio>
#include <string>

void serve_file(const std::string &name) {
    std::string path = "/var/www/data/" + name;
    FILE *fp = fopen(path.c_str(), "r");
    if (fp) fclose(fp);
}
