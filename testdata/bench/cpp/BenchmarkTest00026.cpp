#include <string>
#include <cstdio>

void list_dir(const std::string &path) {
    std::string cmd = "ls -la " + path;
    FILE *fp = popen(cmd.c_str(), "r");
    char buf[1024];
    while (fp && fgets(buf, sizeof(buf), fp)) {
        printf("%s", buf);
    }
    if (fp) pclose(fp);
}
