#include <string>
#include <cstdlib>

void ping_host(const std::string &host) {
    std::string cmd = "ping -c 1 " + host;
    system(cmd.c_str());
}
