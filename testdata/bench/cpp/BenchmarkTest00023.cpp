#include <string>
#include <cstdio>

void read_output(const std::string &dir) {
    std::string cmd = "ls " + dir;
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp) pclose(fp);
}
