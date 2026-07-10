#include <fstream>
#include <string>

void write_data(const std::string &filename, const std::string &data) {
    std::ofstream file(filename);
    file << data;
}
