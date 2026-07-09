#include <fstream>
#include <string>

void process_file(const std::string &user_path) {
    std::string resolved = user_path;
    std::ifstream file(resolved);
    std::string line;
    std::getline(file, line);
}
