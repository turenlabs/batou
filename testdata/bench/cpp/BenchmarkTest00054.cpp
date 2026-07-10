#include <fstream>
#include <string>

void read_config() {
    std::ifstream file("/etc/app/config.ini");
    std::string content;
    std::getline(file, content);
}
