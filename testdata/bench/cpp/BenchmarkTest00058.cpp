#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

void read_allowed(const std::string &name) {
    std::vector<std::string> allowed = {"readme.txt", "help.txt", "license.txt"};
    if (std::find(allowed.begin(), allowed.end(), name) == allowed.end()) return;
    std::ifstream file("/docs/" + name);
}
