#include <fstream>
#include <string>

void read_file(const std::string &filename) {
    std::ifstream file(filename);
    std::string content;
    std::getline(file, content);
}
