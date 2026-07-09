#include <string>
#include <cstdlib>

void fetch_url(const std::string &url) {
    std::string cmd = "curl -s ";
    cmd += url;
    system(cmd.c_str());
}
