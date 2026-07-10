#include <filesystem>
#include <fstream>
#include <string>

void read_file(const std::string &filename) {
    auto canonical = std::filesystem::canonical("/var/www/data/" + filename);
    if (!canonical.string().starts_with("/var/www/data/")) return;
    std::ifstream file(canonical);
}
